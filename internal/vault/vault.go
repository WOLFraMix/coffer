// Package vault — зашифрованное хранилище секретов Coffer.
//
// Формат файла: magic | версия | соль | nonce | AES-256-GCM(JSON).
// Ключ шифрования выводится из мастер-пароля через argon2id
// (параметры подобраны так, чтобы деривация занимала ~0.3-0.5с —
// намеренно медленно, чтобы удорожать перебор паролей).
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

// Заголовок файла.
var magic = []byte("COFF")

const (
	version      byte = 1
	saltLen           = 16        // байт соли: 128 бит, стандарт для argon2
	nonceLen          = 12        // стандартный размер nonce для GCM
	argonMemory       = 64 * 1024 // 64 МБ — жрём память, а не только CPU
	argonTime         = 3         // число итераций
	argonThreads      = 4         // под ваш i7-13620H (8 ядер, 4 хватит)
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

// Open читает и расшифровывает сейф.
// Неверный пароль → ошибка (GCM-аутентификация не пройдёт).
func (v *Vault) Open(password string) ([]Entry, error) {
	raw, err := os.ReadFile(v.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	salt, nonce, ciphertext, err := parseHeader(raw)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(deriveKey(password, salt))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Это и есть «неверный пароль»: GCM падает на проверке тега.
		return nil, ErrWrongPassword
	}

	var entries []Entry
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		return nil, fmt.Errorf("corrupted vault: %w", err)
	}
	return entries, nil
}

// Save шифрует и записывает сейф. Каждый вызов:
//   - берёт ту же соль (ключ не меняется при том же пароле),
//     но НОВЫЙ nonce — переиспользование пары (ключ, nonce)
//     в GCM фатально снижает безопасность;
//   - пишет файл атомарно: сначала во временный файл, потом rename.
func (v *Vault) Save(password string, entries []Entry) error {
	if len(entries) == 0 {
		return errors.New("refusing to save empty vault")
	}

	// Соль: читаем из существующего файла или генерируем новую.
	salt, err := v.loadSalt()
	if err != nil {
		return err
	}
	if salt == nil {
		salt = make([]byte, saltLen)
		if _, err := rand.Read(salt); err != nil {
			return fmt.Errorf("rng: %w", err)
		}
	}

	block, err := aes.NewCipher(deriveKey(password, salt))
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

	// Атомарная запись: сбой питания посреди записи не оставит
	// наполовину испорченный сейф — rename атомарен на уровне ФС.
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil { // только владелец
		return err
	}
	return os.Rename(tmp, v.path)
}

// --- внутренности ---

// deriveKey — argon2id: пароль+соль → 32-байтный ключ AES.
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, keyLen)
}

// parseHeader разбирает шапку файла и возвращает компоненты.
func parseHeader(raw []byte) (salt, nonce, ciphertext []byte, err error) {
	// 4 (magic) + 1 (версия) + 1 (длина соли) + соль + 1 (длина nonce) + nonce
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
	saltLen := int(raw[pos])
	pos++
	if len(raw) < pos+saltLen+1 {
		return nil, nil, nil, errors.New("truncated header")
	}
	salt = raw[pos : pos+saltLen]
	pos += saltLen

	nonceLen := int(raw[pos])
	pos++
	if len(raw) < pos+nonceLen {
		return nil, nil, nil, errors.New("truncated header")
	}
	nonce = raw[pos : pos+nonceLen]
	pos += nonceLen

	return salt, nonce, raw[pos:], nil
}

// buildHeader собирает файл: magic | версия | len(соль)|соль | len(nonce)|nonce | данные.
// Длины пишем явно — формат переживёт смену параметров KDF в будущем.
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

// loadSalt — вытащить соль из существующего сейфа (или nil, если его нет).
func (v *Vault) loadSalt() ([]byte, error) {
	raw, err := os.ReadFile(v.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // новый сейф — соль сгенерируем
	}
	if err != nil {
		return nil, err
	}
	_, salt, _, err := parseHeader(raw)
	return salt, err
}

// Ошибки, на которые UI умеет реагировать осмысленно.
var (
	ErrNotFound      = errors.New("vault not found")       // первый запуск — предложить создать
	ErrWrongPassword = errors.New("wrong master password") // показать «неверный пароль»
)

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
