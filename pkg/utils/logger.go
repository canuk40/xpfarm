package utils

import (
	"fmt"
	"io"
	"math/rand"
	"strings"
	"time"

	"github.com/fatih/color"
)

var (
	bold = color.New(color.Bold).SprintFunc()

	// Global flags
	isDebug  = false
	isSilent = false
)

func SetDebug(debug bool) {
	isDebug = debug
}

func SetSilent(silent bool) {
	isSilent = silent
}

// Bold returns the string in bold
func Bold(a ...interface{}) string {
	return bold(fmt.Sprint(a...))
}

// Prefix returns the colored [xpf] prefix
func prefix(c func(a ...interface{}) string) string {
	return c("[xpf]")
}

// --- Progress Manager Removed ---
// Logic removed as per user request. Use standard logging only.

func printLog(prefixFunc func(a ...interface{}) string, format string, a ...interface{}) {

	msg := fmt.Sprintf(format, a...)

	// Standard Print
	fmt.Printf("%s %s\n", prefix(prefixFunc), msg)
}

func LogInfo(format string, a ...interface{}) {
	if isSilent && !isDebug {
		return
	}
	printLog(Gradient, format, a...)
}

func LogSuccess(format string, a ...interface{}) {
	if isSilent && !isDebug {
		return
	}
	printLog(GradientSuccess, format, a...)
}

func LogError(format string, a ...interface{}) {
	// Always print error
	printLog(GradientError, format, a...)
}

func LogWarning(format string, a ...interface{}) {
	if isSilent && !isDebug {
		return
	}
	printLog(GradientWarning, format, a...)
}

func LogDebug(format string, a ...interface{}) {
	if !isDebug {
		return
	} // Debug logs never show unless debug is on
	printLog(GradientDebug, format, a...)
}

// PrefixWriter is an io.Writer that prepends a prefix to each line
type PrefixWriter struct {
	prefixColor func(a ...interface{}) string
	msgColor    func(a ...interface{}) string // Can be nil for no color
}

func NewPrefixWriter(prefixColor func(a ...interface{}) string, msgColor func(a ...interface{}) string) *PrefixWriter {
	return &PrefixWriter{
		prefixColor: prefixColor,
		msgColor:    msgColor,
	}
}

func (w *PrefixWriter) Write(p []byte) (n int, err error) {
	lines := strings.Split(string(p), "\n")
	for i, line := range lines {
		if line == "" && i == len(lines)-1 {
			continue
		}
		// Based on user request "For example if we have [xpf] Initializing Database... Then only [xpf] should be in colour"
		// We use prefixColor for prefix, and msgColor for text (if provided)
		finalMsg := line
		if w.msgColor != nil {
			finalMsg = w.msgColor(line)
		}
		fmt.Printf("%s %s\n", prefix(w.prefixColor), finalMsg)
	}
	return len(p), nil
}

// GetInfoWriter returns an io.Writer that logs as Info (Gradient prefix, Plain text)
func GetInfoWriter() io.Writer {
	return NewPrefixWriter(Gradient, nil)
}

// PrintGradient prints the text with a random gradient from Purple to [Green,Blue,Yellow,Red]
func PrintGradient(text string) {
	// Seed (using UnixNano for simple randomness on startup)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Targets: Green, Blue, Yellow, Red
	targets := []struct{ r, g, b float64 }{
		{0.0, 255.0, 0.0},   // Green
		{0.0, 191.0, 255.0}, // Blue
		{255.0, 255.0, 0.0}, // Yellow
		{255.0, 0.0, 0.0},   // Red
	}
	target := targets[r.Intn(len(targets))]

	// Calculate line by line gradient for the banner block
	lines := strings.Split(text, "\n")
	startR, startG, startB := 128.0, 0.0, 128.0 // Purple

	for i, line := range lines {
		if line == "" {
			fmt.Println()
			continue
		}
		// Interpolate color for this line
		t := float64(i) / float64(len(lines)-1)
		r := uint8(startR + t*(target.r-startR))
		g := uint8(startG + t*(target.g-startG))
		b := uint8(startB + t*(target.b-startB))

		fmt.Printf("\033[38;2;%d;%d;%dm%s\033[0m\n", r, g, b, line)
	}
}

// Gradient (Default Info/Blue target)
func Gradient(a ...interface{}) string {
	return GradientTo(0.0, 191.0, 255.0, a...) // DeepSkyBlue
}

// GradientSuccess (Green target)
func GradientSuccess(a ...interface{}) string {
	return GradientTo(0.0, 255.0, 0.0, a...)
}

// GradientError (Red target)
func GradientError(a ...interface{}) string {
	return GradientTo(255.0, 0.0, 0.0, a...)
}

// GradientWarning (Yellow target)
func GradientWarning(a ...interface{}) string {
	return GradientTo(255.0, 255.0, 0.0, a...)
}

// GradientDebug (Magenta target)
func GradientDebug(a ...interface{}) string {
	return GradientTo(255.0, 0.0, 255.0, a...)
}

// GradientTo creates a gradient string from Purple to TargetRGB
func GradientTo(endR, endG, endB float64, a ...interface{}) string {
	text := fmt.Sprint(a...)
	runes := []rune(text)
	startR, startG, startB := 128.0, 0.0, 128.0 // Purple

	var sb strings.Builder
	l := len(runes)
	for i, r := range runes {
		t := float64(0)
		if l > 1 {
			t = float64(i) / float64(l-1)
		}
		rr := uint8(startR + t*(endR-startR))
		gg := uint8(startG + t*(endG-startG))
		bb := uint8(startB + t*(endB-startB))

		sb.WriteString(fmt.Sprintf("\033[38;2;%d;%d;%dm%c", rr, gg, bb, r))
	}
	sb.WriteString("\033[0m")
	return sb.String()
}
