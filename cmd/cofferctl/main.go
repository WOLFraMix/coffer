// cofferctl — консольная утилита-диагност сейфа Coffer.
// Команды: open (проверить пароль), create (создать сейф из консоли),
// inspect (разбор файла), reset (удалить сейф целиком).
package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	case "create":
		create(path)
	case "inspect":
		inspect(path)
	case "reset":
		reset(path)
	default:
		openFlow(path)
	}
}

func readPassword(prompt string) string {
	fmt.Print(prompt)
	pw, _ := bufio.NewReader(os.Stdin).ReadString('\n') //nolint:errcheck // консольный диагност
	return strings.TrimSuffix(strings.TrimSuffix(pw, "\n"), "\r")
}

// create — бисекция: если сейф, созданный из CLI, открывается из GUI,
// проблема в пути создания UI; если нет — в пути разблокировки UI.
// Перед выходом сейф проверяется СВЕЖИМ экземпляром Vault: соль
// читается из файла заново, ровно как это сделает другой процесс.
func create(path string) {
	if vault.New(path).Exists() {
		fmt.Println("Сейф уже существует. Сначала: cofferctl reset")
		os.Exit(1)
	}
	pw1 := readPassword("Придумайте пароль: ")
	pw2 := readPassword("Повторите пароль:   ")
	if pw1 != pw2 {
		fmt.Println("ОШИБКА: пароли не совпадают")
		os.Exit(1)
	}
	entries := []vault.Entry{{
		Name: "example@mail.com", Issuer: "Пример",
		Secret: "JBSWY3DPEHPK3PXP", CreatedAt: time.Now(),
	}}
	if err := vault.New(path).Save(pw1, entries); err != nil {
		fmt.Println("ОШИБКА:", err)
		os.Exit(1)
	}

	// Самопроверка СВЕЖИМ экземпляром: у него нет кэша соли, она
	// читается из файла — ровно как при запуске нового процесса.
	// Ловит баг «nonce вместо соли» в момент создания, а не при входе.
	if _, err := vault.New(path).Open(pw1); err != nil {
		fmt.Println("БАГ: сейф создан, но не открывается заново:", err)
		os.Exit(1)
	}
	fmt.Println("OK: сейф создан и проверен повторным чтением.")
}

func openFlow(path string) {
	st, err := os.Stat(path)
	if err != nil {
		fmt.Println("Файл не найден:", err)
		os.Exit(1)
	}
	fmt.Printf("Размер: %d байт (минимум валидного: 53)\n", st.Size())

	pw := readPassword("Введите пароль: ")
	entries, err := vault.New(path).Open(pw)
	switch {
	case err == nil:
		fmt.Printf("OK: сейф открылся, аккаунтов: %d\n", len(entries))
		for _, e := range entries {
			fmt.Printf("  - %s / %s\n", e.Issuer, e.Name)
		}
	case errors.Is(err, vault.ErrCorrupted):
		fmt.Println("ОШИБКА: файл сейфа повреждён. Лечится: cofferctl reset")
		os.Exit(1)
	case errors.Is(err, vault.ErrWrongPassword):
		fmt.Println("ОШИБКА: неверный мастер-пароль")
		os.Exit(1)
	default:
		fmt.Println("ОШИБКА:", err)
		os.Exit(1)
	}
}

func inspect(path string) {
	raw, err := os.ReadFile(path) //nolint:gosec // путь из DefaultPath приложения
	if err != nil {
		fmt.Println("Файл не найден:", err)
		os.Exit(1)
	}
	fmt.Printf("Размер: %d байт (минимум валидного: 53)\n", len(raw))
	if len(raw) < 6 {
		fmt.Println("Файл короче шапки — обрезан.")
		return
	}
	sLen := int(raw[5])
	if len(raw) < 6+sLen+1 {
		fmt.Println("Шапка обрезана — файл повреждён.")
		return
	}
	salt := raw[6 : 6+sLen]
	pos := 6 + sLen
	nLen := int(raw[pos])
	pos++
	if len(raw) < pos+nLen {
		fmt.Println("Шапка обрезана — файл повреждён.")
		return
	}
	nonce := raw[pos : pos+nLen]
	pos += nLen
	fmt.Printf("Magic: %q  версия: %d\n", string(raw[0:4]), raw[4])
	fmt.Printf("Соль  (%2d байт): %s\n", sLen, hex.EncodeToString(salt))
	fmt.Printf("Nonce (%2d байт): %s\n", nLen, hex.EncodeToString(nonce))
	fmt.Printf("Шифротекст: %d байт\n", len(raw)-pos)
}

func reset(path string) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		fmt.Println("ОШИБКА:", err)
		os.Exit(1)
	}
	dir := filepath.Dir(path)
	entries, _ := os.ReadDir(dir) //nolint:errcheck // диагностика
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, filepath.Base(path)+".") && strings.HasSuffix(name, ".tmp") {
			_ = os.Remove(filepath.Join(dir, name)) //nolint:errcheck // диагностика
		}
	}
	fmt.Println("Сейф удалён (если существовал). Запустите приложение и создайте новый.")
}
