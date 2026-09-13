package tui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"tuxproxy/internal/banner"

	"golang.org/x/term"
)

// MenuItem представляет элемент интерактивного терминального меню
type MenuItem struct {
	Key         string
	Title       string
	Description string
	Active      bool
}

// SelectPrompt отображает интерактивное меню с навигацией по клавиатуре
func SelectPrompt(title string, items []MenuItem, defaultIndex int) (int, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return fallbackPrompt(title, items, defaultIndex)
	}

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fallbackPrompt(title, items, defaultIndex)
	}
	defer func() {
		_ = term.Restore(fd, oldState)
		fmt.Print("\r\n")
	}()

	selectedIndex := defaultIndex
	if selectedIndex < 0 || selectedIndex >= len(items) {
		selectedIndex = 0
	}

	buf := make([]byte, 3)

	render := func() {
		fmt.Print("\033[H\033[2J") // Очистка экрана
		fmt.Print(banner.SmallBanner())
		fmt.Printf("\r\n  %s%s%s%s\r\n", banner.Bold, banner.BrightWhite, title, banner.Reset)
		fmt.Printf("  %sНавигация: [↑/↓] или [0-9], Выбор: [Enter], Выход: [Esc/q]%s\r\n\r\n", banner.Dim, banner.Reset)

		for i, item := range items {
			prefix := "    "
			indicator := "[ ]"
			color := banner.White

			if i == selectedIndex {
				prefix = fmt.Sprintf("  %s> %s", banner.BrightCyan, banner.Reset)
				indicator = fmt.Sprintf("%s[*]%s", banner.BrightCyan, banner.Reset)
				color = fmt.Sprintf("%s%s", banner.Bold, banner.BrightWhite)
			} else {
				indicator = fmt.Sprintf("%s[ ]%s", banner.Dim, banner.Reset)
			}

			tag := ""
			if item.Active {
				tag = fmt.Sprintf(" %s[АКТИВНО]%s", banner.BrightGreen, banner.Reset)
			}

			fmt.Printf("\r%s%s %s%s%s%s\r\n", prefix, indicator, color, item.Title, banner.Reset, tag)
			if item.Description != "" {
				fmt.Printf("\r         %s%s%s\r\n", banner.Dim, item.Description, banner.Reset)
			}
		}
	}

	for {
		render()

		n, err := os.Stdin.Read(buf)
		if err != nil {
			return -1, err
		}

		if n == 1 {
			switch buf[0] {
			case 3: // Ctrl+C
				return -1, fmt.Errorf("прервано пользователем")
			case 'q', 'Q', 27: // 'q' или ESC
				return -1, nil
			case 13, 10: // Enter
				return selectedIndex, nil
			case 'k': // vim up
				if selectedIndex > 0 {
					selectedIndex--
				}
			case 'j': // vim down
				if selectedIndex < len(items)-1 {
					selectedIndex++
				}
			default:
				if buf[0] >= '1' && int(buf[0]-'1') < len(items) {
					return int(buf[0] - '1'), nil
				}
			}
		} else if n == 3 && buf[0] == 27 && buf[1] == 91 {
			switch buf[2] {
			case 65: // Up Arrow
				if selectedIndex > 0 {
					selectedIndex--
				}
			case 66: // Down Arrow
				if selectedIndex < len(items)-1 {
					selectedIndex++
				}
			}
		}
	}
}

// fallbackPrompt обрабатывает нетерминальный режим (пайпы, скрипты)
func fallbackPrompt(title string, items []MenuItem, defaultIndex int) (int, error) {
	fmt.Printf("\n%s\n", title)
	for i, item := range items {
		active := ""
		if item.Active {
			active = " [АКТИВНО]"
		}
		fmt.Printf(" [%d] %s%s\n", i+1, item.Title, active)
	}
	fmt.Printf("Выберите пункт [1-%d] (по умолчанию %d): ", len(items), defaultIndex+1)

	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultIndex, nil
	}

	var choice int
	if _, err := fmt.Sscanf(line, "%d", &choice); err == nil && choice >= 1 && choice <= len(items) {
		return choice - 1, nil
	}
	return defaultIndex, nil
}

// ReadInput запрашивает ввод строки со значением по умолчанию
func ReadInput(prompt, defaultValue string) string {
	fmt.Printf("  %s%s%s [%s%s%s]: ", banner.BrightCyan, prompt, banner.Reset, banner.Dim, defaultValue, banner.Reset)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultValue
	}
	return line
}
