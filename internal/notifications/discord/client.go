package discord

import (
	"fmt"
	"log"
	"strings"
	"time"

	"xpfarm/internal/core"
	"xpfarm/internal/database"

	"github.com/bwmarrin/discordgo"
)

type ScanManager interface {
	StartScan(target, asset string, excludeCF bool)
	StopScan(target string)
	GetActiveScans() []core.ActiveScanData
}

type Client struct {
	Session   *discordgo.Session
	ChannelID string
	Scanner   ScanManager
}

func NewClient(token, channelID string, scanner ScanManager) (*Client, error) {
	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		return nil, err
	}

	client := &Client{
		Session:   dg,
		ChannelID: channelID,
		Scanner:   scanner,
	}

	dg.AddHandler(client.messageCreate)
	return client, nil
}

func (c *Client) Start() error {
	err := c.Session.Open()
	if err != nil {
		return fmt.Errorf("error opening connection: %v", err)
	}

	if c.ChannelID != "" {
		dm, err := c.Session.UserChannelCreate(c.ChannelID)
		if err == nil && dm != nil {
			log.Printf("[Discord] Resolved User ID %s to DM Channel %s", c.ChannelID, dm.ID)
			c.ChannelID = dm.ID
		}
	}

	log.Println("[Discord] Bot is now running.")
	return nil
}

func (c *Client) Stop() {
	c.Session.Close()
}

func (c *Client) SendNotification(title, message string, color int) {
	if c.ChannelID == "" {
		return
	}
	embed := &discordgo.MessageEmbed{
		Title:       title,
		Description: message,
		Color:       color,
		Footer: &discordgo.MessageEmbedFooter{
			Text: "XPFarm Automated Scanner",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}
	_, err := c.Session.ChannelMessageSendEmbed(c.ChannelID, embed)
	if err != nil {
		log.Printf("[Discord] Error sending message: %v", err)
	}
}

func (c *Client) messageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	if m.Author.ID == s.State.User.ID {
		return
	}
	if c.ChannelID != "" && m.ChannelID != c.ChannelID {
		return
	}

	args := strings.Fields(m.Content)
	if len(args) == 0 {
		return
	}
	cmd := strings.ToLower(args[0])

	switch cmd {
	case "!help":
		c.sendEmbed(s, m.ChannelID, "🤖 XPFarm Bot Commands", "Here are the available commands:", 0x3b82f6,
			[]*discordgo.MessageEmbedField{
				{Name: "!scan <target> [asset]", Value: "Scan a single target.", Inline: false},
				{Name: "!scan asset <AssetGroup>", Value: "Scan all targets in an Asset Group.", Inline: false},
				{Name: "!stop [target|asset]", Value: "Stop all scans, or specific target.", Inline: false},
				{Name: "!scans", Value: "List currently running scans.", Inline: false},
				{Name: "!assets", Value: "List all Asset Groups.", Inline: false},
				{Name: "!ping", Value: "Check bot status.", Inline: false},
			})

	case "!ping":
		if _, err := s.ChannelMessageSend(m.ChannelID, "Pong! 🏓"); err != nil {
			log.Printf("[Discord] Error sending pong: %v", err)
		}

	case "!scans":
		active := c.Scanner.GetActiveScans()
		if len(active) == 0 {
			c.sendEmbed(s, m.ChannelID, "Active Scans", "No scans currently running.", 0x9ca3af, nil)
		} else {
			var lines []string
			for _, scan := range active {
				lines = append(lines, fmt.Sprintf("- **%s** (Asset: %s)", scan.Target, scan.Asset))
			}
			desc := strings.Join(lines, "\n")
			c.sendEmbed(s, m.ChannelID, "Active Scans", desc, 0x10b981, nil)
		}

	case "!assets":
		var assets []database.Asset
		database.GetDB().Find(&assets)
		if len(assets) == 0 {
			c.sendEmbed(s, m.ChannelID, "Asset Groups", "No assets found.", 0x9ca3af, nil)
		} else {
			list := ""
			for _, a := range assets {
				list += fmt.Sprintf("- **%s** (ID: %d)\n", a.Name, a.ID)
			}
			c.sendEmbed(s, m.ChannelID, "Asset Groups", list, 0x8b5cf6, nil)
		}

	case "!scan":
		if len(args) < 2 {
			c.sendEmbed(s, m.ChannelID, "Error", "Usage: `!scan <target> [asset]` or `!scan asset <AssetGroup>`", 0xef4444, nil)
			return
		}

		// Subcommand: !scan asset <Name>
		if strings.ToLower(args[1]) == "asset" {
			if len(args) < 3 {
				c.sendEmbed(s, m.ChannelID, "Error", "Usage: `!scan asset <AssetGroup>`", 0xef4444, nil)
				return
			}
			assetName := args[2]
			var asset database.Asset
			if err := database.GetDB().Preload("Targets").Where("name = ?", assetName).First(&asset).Error; err != nil {
				c.sendEmbed(s, m.ChannelID, "Error", fmt.Sprintf("Asset Group '**%s**' not found.", assetName), 0xef4444, nil)
				return
			}

			count := 0
			for _, t := range asset.Targets {
				go c.Scanner.StartScan(t.Value, asset.Name, true)
				count++
			}
			c.sendEmbed(s, m.ChannelID, "Bulk Scan Started", fmt.Sprintf("Triggered scans for **%d** targets in group **%s**.", count, asset.Name), 0x10b981, nil)
			return
		}

		// Single Target Scan
		target := args[1]
		asset := "Default"
		if len(args) > 2 {
			asset = args[2]
		}
		c.sendEmbed(s, m.ChannelID, "Scan Started", fmt.Sprintf("Target: **%s**\nAsset: %s", target, asset), 0x34d399, nil)
		go c.Scanner.StartScan(target, asset, true)

	case "!stop":
		if len(args) < 2 {
			// Stop All
			c.Scanner.StopScan("")
			c.sendEmbed(s, m.ChannelID, "Stopped", "Stopping ALL running scans.", 0xef4444, nil)
			return
		}
		// Stop specific target or asset? Manager StopScan supports target name only right now.
		// Todo: Support stopping by Asset? For now, we assume arg is target.
		target := args[1]
		c.Scanner.StopScan(target)
		c.sendEmbed(s, m.ChannelID, "Stopped", fmt.Sprintf("Stopping scan for target: **%s**", target), 0xef4444, nil)
		// NOTE: If user provides Asset Name, it won't work unless we implement finding targets by asset and stopping them.
		// For now improved Stop logic is per target.
	}
}

func (c *Client) sendEmbed(s *discordgo.Session, channelID, title, desc string, color int, fields []*discordgo.MessageEmbedField) {
	embed := &discordgo.MessageEmbed{
		Title:       title,
		Description: desc,
		Color:       color,
		Fields:      fields,
		Footer:      &discordgo.MessageEmbedFooter{Text: "XPFarm Automated Scanner"},
		Timestamp:   time.Now().Format(time.RFC3339),
	}
	if _, err := s.ChannelMessageSendEmbed(channelID, embed); err != nil {
		log.Printf("[Discord] Error sending embed: %v", err)
	}
}
