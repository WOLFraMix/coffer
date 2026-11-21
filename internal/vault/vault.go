// Package vault — зашифрованное хранилище секретов Coffer.
//
// Формат файла: magic | версия | len(соль) | соль | len(nonce) | nonce | AES-256-GCM(JSON).
// Ключ выводится из мастер-пароля через argon2id.
//
// Важно: один сейф — один процесс. Salt кэшируется в экземпляре Vault,
// поэтому ключ и соль невозможно разъединить внутри одного процесса.
// Два параллельных экземпляра приложения не поддерживаются.
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

var (
	ErrNotFound      = errors.New("vault not found")         // сейфа нет — первый запуск
	ErrWrongPassword = errors.New("wrong master password")   // пароль не подошёл
	ErrCorrupted     = errors.New("vault file is corrupted") // файл бит/обрезан
)

var magic = []byte("COFF")

const (
	version      byte = 1
	saltLen           = 16
	nonceLen          = 12
	argonMemory       = 64 * 1024 // килобайты — так ждёт argon2.IDKey
	argonTime         = 3
	argonThreads      = 4
	keyLen            = 32

	// Минимальный валидный размер: шапка 35 + тег GCM 16.
	// Файл короче — гарантированно обрезан, GCM там не вместится.
	minFileLen = 35 + 16
)

// Entry — один аккаунт в сейфе.
type Entry struct {
	Name      string    `json:"name"`
	Issuer    string    `json:"issuer"`
	Secret    string    `json:"secret"`
	CreatedAt time.Time `json:"created_at"`
}

// Vault — сейф, привязанный к файлу на диске.
type Vault struct {
	path string
	salt []byte // кэш: одна соль на всё время жизни экземпляра
}

func New(path string) *Vault  { return &Vault{path: path} }
func (v *Vault) Path() string { return v.path }

func (v *Vault) Exists() bool {
	_, err := os.Stat(v.path)
	return err == nil
}

// getSalt возвращает соль: из кэша или читает из файла.
// Кэш гарантирует: все записи этого экземпляра шифруются ключом
// от ТОЙ ЖЕ соли, что лежит в заголовке файла, — расхождение
// ключа и соли, которое ломало сейф навсегда, стало невозможным.
func (v *Vault) getSalt() ([]byte, error) {
	if v.salt != nil {
		return v.salt, nil
	}
	raw, err := os.ReadFile(v.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // нового сейфа нет — сгенерируем при Save
	}
	if err != nil {
		return nil, err
	}
	_, salt, _, err := parseHeader(raw)
	if err != nil {
		return nil, err
	}
	v.salt = salt
	return salt, nil
}

// Save создаёт/перезаписывает сейф по мастер-паролю.
func (v *Vault) Save(password string, entries []Entry) error {
	if len(entries) == 0 {
		return errors.New("refusing to save empty vault")
	}
	salt, err := v.getSalt()
	if err != nil {
		return err
	}
	if salt == nil {
		salt = make([]byte, saltLen)
		if _, err := rand.Read(salt); err != nil {
			return fmt.Errorf("rng: %w", err)
		}
		v.salt = salt // запомнили: ключ и соль больше не разъедутся
	}
	return v.write(deriveKey(password, salt), salt, entries)
}

// Open читает и расшифровывает сейф по мастер-паролю.
func (v *Vault) Open(password string) ([]Entry, error) {
	key, err := v.DeriveKey(password)
	if err != nil {
		return nil, err
	}
	return v.OpenWithKey(key)
}

// DeriveKey выводит из пароля 32-байтный ключ по соли этого сейфа.
func (v *Vault) DeriveKey(password string) ([]byte, error) {
	salt, err := v.getSalt()
	if err != nil {
		return nil, err
	}
	if salt == nil {
		return nil, ErrNotFound
	}
	return deriveKey(password, salt), nil
}

// SaveWithKey перезаписывает сейф по готовому ключу.
// Пустой список разрешён: пользователь имеет право удалить все аккаунты.
func (v *Vault) SaveWithKey(key []byte, entries []Entry) error {
	salt, err := v.getSalt()
	if err != nil {
		return err
	}
	if salt == nil {
		return errors.New("vault not initialised: use Save(password) first")
	}
	return v.write(key, salt, entries)
}

// OpenWithKey расшифровывает сейф по готовому ключу.
func (v *Vault) OpenWithKey(key []byte) ([]Entry, error) {
	raw, err := os.ReadFile(v.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(raw) < minFileLen {
		// Обрезанный файл — НЕ «неверный пароль». Раньше мы врали
		// пользователю, называя обрыв файла плохим паролем.
		return nil, ErrCorrupted
	}

	_, nonce, ciphertext, err := parseHeader(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCorrupted, err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.Overhead() {
		return nil, ErrCorrupted
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Здесь GCM падает только если ключ не подходит к этому
		// шифротексту: неверный пароль или подделка файла.
		return nil, ErrWrongPassword
	}

	var entries []Entry
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCorrupted, err)
	}
	return entries, nil
}

// write шифрует и записывает сейф. Новая пара nonce — каждый раз.
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

	// Уникальное имя tmp НА ПРОЦЕСС: раньше имя было общим, и два
	// экземпляра затирали tmp друг друга — на диск уходил усечённый
	// файл. Это и был источник «неверного пароля» с целым паролем.
	tmp := fmt.Sprintf("%s.%d.tmp", v.path, os.Getpid())

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(out); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	// fsync: байты реально на диске ДО rename — при сбое питания
	// сейф останется либо старым, либо новым, но не обрезанным.
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, v.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, keyLen)
}

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
