package banner

import (
	"fmt"
	"strings"
)

// ANSI escape codes
const (
	Reset     = "\033[0m"
	Bold      = "\033[1m"
	Dim       = "\033[2m"
	Underline = "\033[4m"

	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"

	BrightBlack  = "\033[90m"
	BrightRed    = "\033[91m"
	BrightGreen  = "\033[92m"
	BrightYellow = "\033[93m"
	BrightBlue   = "\033[94m"
	BrightCyan   = "\033[96m"
	BrightWhite  = "\033[97m"
)

const Version = "1.0.0"

// PrintBanner outputs a strict, authoritative security header
func PrintBanner() {
	fmt.Println(BannerString())
}

// BannerString returns a clean, military/enterprise security header
func BannerString() string {
	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("  %s%s========================================================================%s\n", Bold, BrightCyan, Reset))
	sb.WriteString(fmt.Sprintf("  %s%s TUXPROXY%s %s:: Комплекс изоляции процессов и защиты сетевого трафика v%s%s\n", Bold, BrightWhite, Reset, Dim, Version, Reset))
	sb.WriteString(fmt.Sprintf("  %s Среда предотвращения утечек (Zero-Leak) | Маршрутизация Tor | Anti-DPI%s\n", Dim, Reset))
	sb.WriteString(fmt.Sprintf("  %s%s========================================================================%s\n", Bold, BrightCyan, Reset))
	return sb.String()
}

// SmallBanner returns a compact single-line header
func SmallBanner() string {
	return fmt.Sprintf("  %s%s[TUXPROXY v%s]%s %sИзоляция процессов и сетевого трафика%s\n",
		Bold, BrightCyan, Version, Reset, Dim, Reset)
}

// Security & Status indicators
func TagOK(msg string) string {
	return fmt.Sprintf("  %s%s[+]%s %s", Bold, BrightGreen, Reset, msg)
}

func TagInfo(msg string) string {
	return fmt.Sprintf("  %s%s[*]%s %s", Bold, BrightCyan, Reset, msg)
}

func TagWarn(msg string) string {
	return fmt.Sprintf("  %s%s[!]%s %s%s%s", Bold, BrightYellow, Reset, Yellow, msg, Reset)
}

func TagErr(msg string) string {
	return fmt.Sprintf("  %s%s[-]%s %s%s%s", Bold, BrightRed, Reset, BrightRed, msg, Reset)
}

func TagSecure(msg string) string {
	return fmt.Sprintf("  %s%s[БЕЗОПАСНОСТЬ]%s %s", Bold, BrightGreen, Reset, msg)
}

func TagAction(msg string) string {
	return fmt.Sprintf("  %s%s[ДЕЙСТВИЕ]%s %s", Bold, BrightWhite, Reset, msg)
}

// ProgressBar renders a clean, technical progress bar
func ProgressBar(percent int, description string) string {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	width := 28
	completed := (percent * width) / 100
	remaining := width - completed

	var bar strings.Builder
	bar.WriteString(fmt.Sprintf("%s%s[%s", Bold, BrightWhite, Reset))
	bar.WriteString(fmt.Sprintf("%s%s%s", BrightGreen, strings.Repeat("#", completed), Reset))
	bar.WriteString(fmt.Sprintf("%s%s%s", BrightBlack, strings.Repeat(".", remaining), Reset))
	bar.WriteString(fmt.Sprintf("%s%s]%s %s%3d%%%s %s(%s)%s",
		Bold, BrightWhite, Reset, Bold, percent, Reset, Dim, description, Reset))

	return bar.String()
}

// BoxSection formats key technical data into a strict terminal table
func BoxSection(title string, lines []string) string {
	var sb strings.Builder
	width := 72

	titleLen := len([]rune(title))
	dashLen := width - titleLen - 5
	if dashLen < 2 {
		dashLen = 2
	}

	sb.WriteString(fmt.Sprintf("  %s+-- [ %s%s%s ] %s+%s\n", BrightCyan, Bold, title, Reset, strings.Repeat("-", dashLen), BrightCyan))

	for _, line := range lines {
		cleanLen := len([]rune(stripANSI(line)))
		pad := width - cleanLen - 2
		if pad < 0 {
			pad = 0
		}
		sb.WriteString(fmt.Sprintf("  %s|%s %s%s %s|%s\n", BrightCyan, Reset, line, strings.Repeat(" ", pad), BrightCyan, Reset))
	}

	sb.WriteString(fmt.Sprintf("  %s+-%s-+%s\n", BrightCyan, strings.Repeat("-", width), Reset))
	return sb.String()
}

func stripANSI(str string) string {
	var sb strings.Builder
	inEsc := false
	for _, r := range str {
		if r == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEsc = false
			}
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
