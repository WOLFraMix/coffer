// cofferctl — консольная утилита-диагност сейфа Coffer.
// Команды: open (проверить пароль), inspect (разбор файла),
// reset (удалить сейф целиком).
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/WOLFraMix/coffer/internal/vault"
)

func main() {
	path, err := vault.DefaultPath()
	if err != nil {
		fmt.Println("путь:", err)
		os.Exit(1)
	}
	fmt.Println("Сейф:", path)

	cmd := "open"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "reset":
		reset(path)
	case "inspect":
		inspect(path)
	default:
		openFlow(path)
	}
}

func openFlow(path string) {
	st, err := os.Stat(path)
	if err != nil {
		fmt.Println("Файл не найден:", err)
		os.Exit(1)
	}
	fmt.Printf("Размер: %d байт (минимум валидного файла: 51; меньше — файл обрезан)\n", st.Size())

	fmt.Print("Введите пароль: ")
	pw, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	pw = strings.TrimSuffix(strings.TrimSuffix(pw, "\n"), "\r")

	entries, err := vault.New(path).Open(pw)
	switch err {
	case nil:
		fmt.Printf("OK: сейф открылся, аккаунтов: %d\n", len(entries))
		for _, e := range entries {
			fmt.Printf("  - %s / %s\n", e.Issuer, e.Name)
		}
	case vault.ErrCorrupted:
		fmt.Println("ОШИБКА: файл сейфа повреждён (обрезан). Лечится: cofferctl reset")
		os.Exit(1)
	case vault.ErrWrongPassword:
		fmt.Println("ОШИБКА: неверный мастер-пароль")
		os.Exit(1)
	default:
		fmt.Println("ОШИБКА:", err)
		os.Exit(1)
	}
}

func inspect(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Файл не найден:", err)
		os.Exit(1)
	}
	fmt.Printf("Размер: %d байт\n", len(raw))
	if len(raw) >= 6 {
		fmt.Printf("Magic: %q  версия: %d  заявленная соль: %d байт, nonce: %d байт\n",
			string(raw[0:4]), raw[4], raw[5], raw[5+int(raw[5])+1])
	}
	n := 64
	if len(raw) < n {
		n = len(raw)
	}
	fmt.Println("Первые байты (hex):")
	fmt.Println(hex.Dump(raw[:n]))
}

func reset(path string) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		fmt.Println("ОШИБКА:", err)
		os.Exit(1)
	}
	// Подчищаем tmp-файлы всех процессов.
	dir := filepath.Dir(path)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, filepath.Base(path)+".") && strings.HasSuffix(name, ".tmp") {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
	fmt.Println("Сейф удалён. Запустите приложение и создайте новый.")
}
