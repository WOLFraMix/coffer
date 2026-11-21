// Package vault — зашифрованное хранилище секретов Coffer.
//
// Формат файла: magic | версия | len(соль) | соль | len(nonce) | nonce | AES-256-GCM(JSON).
// Ключ шифрования выводится из мастер-пароля через argon2id
// (параметры подобраны так, чтобы деривация занимала ~0.1-0.5с —
// намеренно медленно, чтобы удорожать перебор паролей).
//
// Два способа работы:
//   - по паролю (Open/Save) — для разблокировки и создания сейфа;
//   - по готовому ключу (OpenWithKey/SaveWithKey) — для App-слоя,
//     который деривирует ключ один раз и не хранит сам пароль.
package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/argon2"
)

// Ошибки, на которые UI умеет реагировать осмысленно.
var (
	ErrNotFound      = errors.New("vault not found")       // первый запуск — предложить создать
	ErrWrongPassword = errors.New("wrong master password") // показать «неверный пароль»
)

// Заголовок файла: опознавательная сигнатура «COFF».
var magic = []byte("COFF")

const (
	version      byte = 1
	saltLen           = 16        // байт соли: 128 бит, стандарт для argon2
	nonceLen          = 12        // стандартный размер nonce для GCM
	argonMemory       = 64 * 1024 // 64 МБ (в килобайтах — так ждёт argon2.IDKey)
	argonTime         = 3         // число итераций argon2
	argonThreads      = 4         // потоки KDF
	keyLen            = 32        // AES-256: ключ 32 байта
)

// Entry — один аккаунт в сейфе.
type Entry struct {
	Name      string    `json:"name"`   // имя аккаунта (user@example.com)
	Issuer    string    `json:"issuer"` // сервис: GitHub, Google...
	Secret    string    `json:"secret"` // Base32-секрет TOTP
	CreatedAt time.Time `json:"created_at"`
}

// Vault — сейф, привязанный к файлу на диске.
type Vault struct {
	path string
}

// New возвращает сейф для файла path (без обращения к диску).
func New(path string) *Vault {
	return &Vault{path: path}
}

// Path — путь к файлу сейфа (нужно App-слою для проверок).
func (v *Vault) Path() string { return v.path }

// Exists — существует ли файл сейфа на диске.
func (v *Vault) Exists() bool {
	_, err := os.Stat(v.path)
	return err == nil
}

// --- парольный API: создание и разблокировка ---

// Save создаёт/перезаписывает сейф по мастер-паролю.
// Соль берётся из существующего файла или генерируется новая.
func (v *Vault) Save(password string, entries []Entry) error {
	if len(entries) == 0 {
		return errors.New("refusing to save empty vault")
	}

	salt, err := v.loadSalt()
	if err != nil {
		return err
	}
	if salt == nil {
		// Нового сейфа нет на диске — генерируем свежую соль.
		salt = make([]byte, saltLen)
		if _, err := rand.Read(salt); err != nil {
			return fmt.Errorf("rng: %w", err)
		}
	}
	return v.write(deriveKey(password, salt), salt, entries)
}

// Open читает и расшифровывает сейф по мастер-паролю.
// Неверный пароль → ErrWrongPassword (GCM-аутентификация не пройдёт).
func (v *Vault) Open(password string) ([]Entry, error) {
	key, err := v.DeriveKey(password)
	if err != nil {
		return nil, err
	}
	return v.OpenWithKey(key)
}

// DeriveKey читает соль из файла и выводит из пароля 32-байтный ключ.
// Вызывается App-слоем один раз при разблокировке: дальше сейф
// работает по ключу, и мастер-пароль нигде не хранится.
func (v *Vault) DeriveKey(password string) ([]byte, error) {
	raw, err := os.ReadFile(v.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	salt, _, _, err := parseHeader(raw)
	if err != nil {
		return nil, err
	}
	return deriveKey(password, salt), nil
}

// --- ключевой API: работа без пароля ---

// SaveWithKey перезаписывает сейф по готовому ключу.
// Пустой список записывать РАЗРЕШЕНО: пользователь имеет право
// удалить все аккаунты. Раньше пустой сейф запрещался — и это
// ломало удаление последнего аккаунта и рассинхронизировало память
// с диском. Защита «не затереть рабочий сейф пустым по ошибке»
// остаётся только в Save (путь создания сейфа).
func (v *Vault) SaveWithKey(key []byte, entries []Entry) error {
	salt, err := v.loadSalt()
	if err != nil {
		return err
	}
	if salt == nil {
		return errors.New("vault not initialized: use Save(password) first")
	}
	return v.write(key, salt, entries)
}

// OpenWithKey расшифровывает сейф по готовому ключу.
func (v *Vault) OpenWithKey(key []byte) ([]Entry, error) {
	return v.open(key)
}

// --- внутренности: единая логика чтения/записи ---

// write шифрует и записывает сейф. Каждый вызов берёт НОВЫЙ nonce:
// переиспользование пары (ключ, nonce) в GCM катастрофично.
// Пишем атомарно: сначала во временный файл, потом rename.
func (v *Vault) write(key, salt []byte, entries []Entry) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("rng: %w", err)
	}

	plaintext, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	out := buildHeader(salt, nonce, ciphertext)

	// 0o600 — права «только владелец»; на Windows работает мягче,
	// но привычка корректна для кроссплатформенности.
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	// Атомарная запись: сбой питания посреди записи не оставит
	// наполовину испорченный сейф — rename атомарен на уровне ФС.
	return os.Rename(tmp, v.path)
}

// open читает файл, разбирает заголовок и расшифровывает данные.
func (v *Vault) open(key []byte) ([]Entry, error) {
	raw, err := os.ReadFile(v.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	_, nonce, ciphertext, err := parseHeader(raw)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Это и есть «неверный пароль» (или испорченный файл):
		// GCM не различает эти случаи — и то, и другое — подделка.
		return nil, ErrWrongPassword
	}

	var entries []Entry
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		return nil, fmt.Errorf("corrupted vault: %w", err)
	}
	return entries, nil
}

// deriveKey — argon2id: пароль+соль → 32-байтный ключ AES.
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, keyLen)
}

// parseHeader разбирает шапку файла и возвращает компоненты.
// Длины соли и nonce хранятся в самом файле — формат переживёт
// смену параметров KDF без миграции (версия в заголовке).
func parseHeader(raw []byte) (salt, nonce, ciphertext []byte, err error) {
	if len(raw) < len(magic)+3 {
		return nil, nil, nil, errors.New("too short")
	}
	if !bytes.Equal(raw[:len(magic)], magic) {
		return nil, nil, nil, errors.New("not a coffer file")
	}
	if raw[len(magic)] != version {
		return nil, nil, nil, fmt.Errorf("unsupported version %d", raw[len(magic)])
	}

	pos := len(magic) + 1
	sLen := int(raw[pos])
	pos++
	if len(raw) < pos+sLen+1 {
		return nil, nil, nil, errors.New("truncated header")
	}
	salt = raw[pos : pos+sLen]
	pos += sLen

	nLen := int(raw[pos])
	pos++
	if len(raw) < pos+nLen {
		return nil, nil, nil, errors.New("truncated header")
	}
	nonce = raw[pos : pos+nLen]
	pos += nLen

	return salt, nonce, raw[pos:], nil
}

// buildHeader собирает файл целиком.
func buildHeader(salt, nonce, ciphertext []byte) []byte {
	out := make([]byte, 0, len(magic)+3+len(salt)+len(nonce)+len(ciphertext))
	out = append(out, magic...)
	out = append(out, version)
	out = append(out, byte(len(salt)))
	out = append(out, salt...)
	out = append(out, byte(len(nonce)))
	out = append(out, nonce...)
	return append(out, ciphertext...)
}

// loadSalt — вытащить соль из существующего сейфа (или nil, если файла нет).
func (v *Vault) loadSalt() ([]byte, error) {
	raw, err := os.ReadFile(v.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // нового сейфа нет — соль сгенерирует write-путь
	}
	if err != nil {
		return nil, err
	}
	_, salt, _, err := parseHeader(raw)
	return salt, err
}

// DefaultPath — %APPDATA%/Coffer/coffer.cof на Windows.
// os.UserConfigDir возвращает нужную папку на всех платформах сразу.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, "Coffer")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "coffer.cof"), nil
}
