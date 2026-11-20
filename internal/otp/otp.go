// Package otp — генерация одноразовых паролей TOTP (RFC 6238).
//
// Реализация совместима с Google Authenticator и большинством
// сервисов: период 30 секунд, SHA-1, 6 цифр, секрет в Base32.
// Пишем сами на stdlib, чтобы понимать алгоритм, а не доверять
// его чёрному ящику.
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
	Period  = 30 * time.Second // окно одного кода
	Digits  = 6                // длина кода
	modulus = 1_000_000        // 10^Digits: остаток даёт 6 цифр
)

// Generate возвращает текущий код и число секунд до его смены.
// now передаётся явно — это делает функцию детерминированной и
// тривиально тестируемой (в тестах подставляем фиксированное время).
func Generate(secret string, now time.Time) (code string, secondsLeft int, err error) {
	key, err := decodeBase32(secret)
	if err != nil {
		return "", 0, fmt.Errorf("bad secret: %w", err)
	}

	// Счётчик времени: сколько 30-секундных окон прошло с эпохи.
	counter := uint64(now.Unix()) / uint64(Period.Seconds())

	// HMAC-SHA1: ключ — секрет, сообщение — счётчик (big-endian).
	mac := hmac.New(sha1.New, key)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Динамическое усечение (RFC 4226, §5.3):
	// младшие 4 бита последнего байта — смещение в 20-байтовом HMAC.
	offset := sum[len(sum)-1] & 0x0f
	// 4 байта со смещения; & 0x7fffffff сбрасывает знаковый бит,
	// чтобы число гарантированно было положительным.
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	code = fmt.Sprintf("%06d", value%modulus)
	secondsLeft = int(Period) - int(now.Unix()%int64(Period.Seconds()))
	return code, secondsLeft, nil
}

// decodeBase32 — парсит секрет, простив пользователю пробелы,
// регистр и пустые строки. Base32 от сервисов бывает и с пробелами
// по 4 символа ("JBSW Y3DP EHPK 3PXP"), чистим обязательно.
func decodeBase32(s string) ([]byte, error) {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if s == "" {
		return nil, errors.New("empty secret")
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}
