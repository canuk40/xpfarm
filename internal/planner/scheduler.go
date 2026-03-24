package planner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"xpfarm/internal/modules"
	"xpfarm/internal/overlord"
	"xpfarm/pkg/utils"

	"gorm.io/gorm"
)

// StepLog carries a structured log line from a step execution.
type StepLog struct {
	StepID  string
	Message string
}

// ExecutePlanWithLogs runs each step in the plan sequentially.
// Progress and output are sent to logCh; the caller is responsible for
// draining logCh until it is closed. The plan's Steps slice is mutated
// in-place with output and status. db is used to persist scan results.
func ExecutePlanWithLogs(ctx context.Context, db *gorm.DB, plan *ScanPlan, logCh chan<- StepLog) error {
	for i := range plan.Steps {
		step := &plan.Steps[i]

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		logCh <- StepLog{StepID: step.StepID, Message: fmt.Sprintf("[%s] Starting: %s/%s on %s", step.StepID, step.Agent, step.Tool, step.Target)}
		step.Status = "running"

		var output string
		var execErr error

		if step.Agent == "builtin" {
			output, execErr = runBuiltinTool(ctx, step, logCh)
		} else {
			output, execErr = runOverlordStep(ctx, step, logCh)
		}

		if execErr != nil {
			step.Status = "failed"
			step.Error = execErr.Error()
			logCh <- StepLog{StepID: step.StepID, Message: fmt.Sprintf("[%s] FAILED: %v", step.StepID, execErr)}
			// Non-fatal: continue with remaining steps
			continue
		}

		step.Output = output
		step.Status = "done"
		logCh <- StepLog{StepID: step.StepID, Message: fmt.Sprintf("[%s] Done. Output length: %d chars", step.StepID, len(output))}
	}
	return nil
}

// runBuiltinTool runs a registered Go module by name.
func runBuiltinTool(ctx context.Context, step *PlanStep, logCh chan<- StepLog) (string, error) {
	mod := modules.Get(step.Tool)
	if mod == nil {
		// Some capability tool names differ from module names — try common aliases
		aliased := toolAlias(step.Tool)
		if aliased != "" {
			mod = modules.Get(aliased)
		}
	}
	if mod == nil {
		return "", fmt.Errorf("builtin module %q not found in registry", step.Tool)
	}
	if !mod.CheckInstalled() {
		return "", fmt.Errorf("module %q is not installed", step.Tool)
	}

	logCh <- StepLog{StepID: step.StepID, Message: fmt.Sprintf("[%s] Running %s on %s...", step.StepID, step.Tool, step.Target)}
	output, err := mod.Run(ctx, step.Target)
	if err != nil {
		// Partial output still valuable
		utils.LogDebug("planner: %s partial error: %v", step.Tool, err)
	}
	return output, err
}

// toolAlias maps Overlord-style tool names to built-in module names.
func toolAlias(tool string) string {
	aliases := map[string]string{
		"subfinder_enum": "subfinder",
		"port_scan":      "naabu",
		"http_probe":     "httpx",
		"vuln_scan":      "nuclei",
		"crawl":          "katana",
		"screenshot":     "gowitness",
		"tech_detect":    "wappalyzer",
		"url_discovery":  "urlfinder",
		"cve_lookup":     "cvemap",
		"service_detect": "nmap",
	}
	return aliases[tool]
}

// runOverlordStep sends a step to the appropriate Overlord agent and polls
// for the response, feeding log lines back to logCh as they arrive.
func runOverlordStep(ctx context.Context, step *PlanStep, logCh chan<- StepLog) (string, error) {
	if status := overlord.CheckConnection(); !status.Connected {
		return "", fmt.Errorf("Overlord is offline — cannot execute agent step %q", step.Agent)
	}

	prompt := buildStepPrompt(step)
	logCh <- StepLog{StepID: step.StepID, Message: fmt.Sprintf("[%s] Sending to Overlord agent %q...", step.StepID, step.Agent)}

	sess, err := overlord.CreateSession(fmt.Sprintf("Plan step %s — %s/%s", step.StepID, step.Agent, step.Tool))
	if err != nil {
		return "", fmt.Errorf("overlord session: %w", err)
	}

	if err := overlord.SendPromptAsync(sess.ID, prompt, ""); err != nil {
		return "", fmt.Errorf("overlord send: %w", err)
	}

	// Poll with progress logs
	deadline := time.Now().Add(5 * time.Minute)
	var lastText string
	var stableCount int
	var lastLen int

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			_ = overlord.AbortSession(sess.ID)
			return "", ctx.Err()
		default:
		}
		time.Sleep(4 * time.Second)

		messages, err := overlord.GetSessionMessages(sess.ID)
		if err != nil {
			continue
		}
		text := extractAssistantText(messages)
		if text != "" {
			if len(text) > lastLen {
				// New content arrived — log a progress tick
				logCh <- StepLog{StepID: step.StepID, Message: fmt.Sprintf("[%s] ← %d chars received...", step.StepID, len(text))}
				lastLen = len(text)
				stableCount = 0
			}
			if text == lastText {
				stableCount++
				if stableCount >= 2 {
					return text, nil
				}
			} else {
				lastText = text
				stableCount = 0
			}
		}
	}

	if lastText != "" {
		return lastText, nil
	}
	return "", fmt.Errorf("Overlord step timed out after 5 minutes")
}

// buildStepPrompt creates a targeted instruction for a specific plan step.
func buildStepPrompt(step *PlanStep) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("You are the %q Overlord agent.\n\n", step.Agent))
	sb.WriteString(fmt.Sprintf("Execute the following task using the %q tool:\n", step.Tool))
	sb.WriteString(fmt.Sprintf("Target: %s\n", step.Target))
	if len(step.Params) > 0 {
		sb.WriteString("Parameters:\n")
		for k, v := range step.Params {
			sb.WriteString(fmt.Sprintf("  %s: %v\n", k, v))
		}
	}
	sb.WriteString(fmt.Sprintf("\nReason this step was selected: %s\n\n", step.Reason))
	sb.WriteString("Perform the task thoroughly. Report all findings, extracted data, and observations. Be concise but complete.")
	return sb.String()
}
