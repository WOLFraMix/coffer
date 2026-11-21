// Package otp — генерация одноразовых паролей TOTP (RFC 6238).
//
// Совместим с Google Authenticator: период 30 секунд, SHA-1, 6 цифр.
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	Period  = 30 * time.Second // окно одного кода (Duration — в наносекундах!)
	Digits  = 6                // длина кода
	modulus = 1_000_000        // 10^Digits: остаток даёт 6 цифр

	// periodSecs — длительность окна в СЕКУНДАХ. Отдельная константа,
	// потому что int(Period) дал бы 30 млрд наносекунд — на этом мы
	// уже погорели: «2999999999с» вместо «30с».
	periodSecs = int64(Period / time.Second)
)

// Generate возвращает текущий код и число секунд до его смены.
// now передаётся явно — функция детерминирована и тривиально тестируема.
func Generate(secret string, now time.Time) (code string, secondsLeft int, err error) {
	key, err := decodeBase32(secret)
	if err != nil {
		return "", 0, fmt.Errorf("bad secret: %w", err)
	}

	// Счётчик времени: сколько 30-секундных окон прошло с эпохи.
	counter := uint64(now.Unix()) / uint64(periodSecs)

	// HMAC-SHA1: ключ — секрет, сообщение — счётчик (big-endian).
	mac := hmac.New(sha1.New, key)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Динамическое усечение (RFC 4226, §5.3).
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	code = fmt.Sprintf("%06d", value%modulus)
	// Остаток окна: сколько секунд прошло в текущем окне, вычитаем из 30.
	secondsLeft = int(periodSecs - now.Unix()%periodSecs)
	return code, secondsLeft, nil
}

// decodeBase32 прощает пробелы, регистр и пустые строки.
func decodeBase32(s string) ([]byte, error) {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if s == "" {
		return nil, errors.New("empty secret")
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}
