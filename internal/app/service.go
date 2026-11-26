// Package app — сервисы для UI: слой между фронтендом и ядром.
// Публичные методы Service Wails превращает в вызываемые из JS функции.
package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/WOLFraMix/coffer/internal/otp"
	"github.com/WOLFraMix/coffer/internal/vault"
)

// Account — метаданные аккаунта для UI. Секрет наружу не отдаём.
type Account struct {
	ID     int    `json:"id"`
	Issuer string `json:"issuer"`
	Name   string `json:"name"`
}

// CodeView — «строка кода»: метаданные + текущий TOTP + счётчик секунд.
type CodeView struct {
	Account
	Code        string `json:"code"`
	SecondsLeft int    `json:"secondsLeft"`
}

// Service — состояние приложения. Все методы под мьютексом:
// Wails может звать их параллельно из разных горутин.
type Service struct {
	mu      sync.Mutex
	v       *vault.Vault
	key     []byte        // производный ключ; пароль после разблокировки не храним
	entries []vault.Entry // расшифрованные данные — только в памяти
	open    bool

	picker FilePicker

	lastTouch time.Time     // последнее действие пользователя
	lockAfter time.Duration // бездействие до автоблокировки
}

// lockAfter по умолчанию: 5 минут бездействия. Позже вынесем в настройки.
const defaultLockAfter = 5 * time.Minute

func NewService(path string) *Service {
	s := &Service{v: vault.New(path), lockAfter: defaultLockAfter}
	// Фоновый сторож: раз в 10 секунд проверяет бездействие и
	// закрывает сейф. Гонится всю жизнь процесса — копейки.
	go s.idleLoop()
	return s
}

// idleLoop — сторож автоблокировки. Опрос Codes() активностью НЕ
// считается: он бежит и когда пользователь ушёл. Только реальные
// касания (Touch) продлевают жизнь открытого сейфа.
func (s *Service) idleLoop() {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for range tick.C {
		s.mu.Lock()
		if s.open && !s.lastTouch.IsZero() && time.Since(s.lastTouch) > s.lockAfter {
			s.lockLocked()
		}
		s.mu.Unlock()
	}
}

// Touch — отметка активности от фронтенда (mousemove/keydown).
func (s *Service) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastTouch = time.Now()
}

// HasVault — есть ли сейф на диске (первый запуск?).
func (s *Service) HasVault() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.v.Exists()
}

// CreateVault — первый запуск: создать сейф с мастер-паролем.
func (s *Service) CreateVault(password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(password) < 8 {
		return errors.New("мастер-пароль — минимум 8 символов")
	}
	if s.v.Exists() {
		return errors.New("сейф уже существует")
	}

	entries := []vault.Entry{{
		Name:      "example@mail.com",
		Issuer:    "Пример",
		Secret:    "JBSWY3DPEHPK3PXP",
		CreatedAt: time.Now(),
	}}
	if err := s.v.Save(password, entries); err != nil {
		return fmt.Errorf("не удалось создать сейф: %w", err)
	}

	// Самопроверка: сейф обязан открываться тем же паролем сразу
	// после создания (ловит порчу файла в момент записи).
	check, err := s.v.Open(password)
	if err != nil {
		return fmt.Errorf("БАГ: сейф создан, но не открывается тем же паролем: %v", err)
	}
	if len(check) != len(entries) {
		return fmt.Errorf("БАГ: после создания в сейфе %d аккаунтов вместо %d", len(check), len(entries))
	}

	key, err := s.v.DeriveKey(password)
	if err != nil {
		return err
	}
	s.key, s.entries, s.open = key, entries, true
	s.lastTouch = time.Now()
	return nil
}

// Unlock — расшифровать сейф мастер-паролем.
func (s *Service) Unlock(password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, err := s.v.DeriveKey(password)
	if err != nil {
		return err
	}
	entries, err := s.v.OpenWithKey(key)
	if err != nil {
		return err
	}
	s.key, s.entries, s.open = key, entries, true
	s.lastTouch = time.Now()
	return nil
}

// Lock — забыть данные в памяти (кнопка или сторож).
func (s *Service) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lockLocked()
}

func (s *Service) lockLocked() {
	s.entries = nil
	s.key = nil
	s.open = false
}

// IsUnlocked — фронтенд спрашивает при старте, чтобы выбрать экран.
func (s *Service) IsUnlocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.open
}

// ResetVault — удалить сейф с диска (без пароля: секреты всё равно
// невосстановимы без него, а файл стёр бы любой процесс от имени юзера).
func (s *Service) ResetVault() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lockLocked()
	if err := s.v.Remove(); err != nil {
		return fmt.Errorf("не удалось удалить сейф: %w", err)
	}
	return nil
}

// Codes — пересчитать текущие TOTP-коды для всех аккаунтов.
func (s *Service) Codes() ([]CodeView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.open {
		return nil, errors.New("vault is locked")
	}
	return s.viewsLocked(time.Now()), nil
}

// AddAccount — добавить аккаунт по секрету из формы.
func (s *Service) AddAccount(issuer, name, secret string) ([]CodeView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.open {
		return nil, errors.New("vault is locked")
	}
	if issuer == "" && name == "" {
		return nil, errors.New("укажите хотя бы имя аккаунта")
	}
	if name == "" {
		name = issuer
	}
	if _, _, err := otp.Generate(secret, time.Now()); err != nil {
		return nil, fmt.Errorf("неверный секрет: %w", err)
	}

	s.entries = append(s.entries, vault.Entry{
		Name: name, Issuer: issuer, Secret: secret, CreatedAt: time.Now(),
	})
	if err := s.v.SaveWithKey(s.key, s.entries); err != nil {
		s.entries = s.entries[:len(s.entries)-1] // откат при ошибке записи
		return nil, fmt.Errorf("не удалось сохранить сейф: %w", err)
	}
	return s.viewsLocked(time.Now()), nil
}

// RemoveAccount — удалить аккаунт по ID (позиция в списке).
func (s *Service) RemoveAccount(id int) ([]CodeView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.open {
		return nil, errors.New("vault is locked")
	}
	if id < 0 || id >= len(s.entries) {
		return nil, fmt.Errorf("нет аккаунта с id=%d", id)
	}

	s.entries = slices.Delete(s.entries, id, id+1)
	if err := s.v.SaveWithKey(s.key, s.entries); err != nil {
		return nil, fmt.Errorf("не удалось сохранить сейф: %w", err)
	}
	return s.viewsLocked(time.Now()), nil
}

// viewsLocked — пересчёт кодов для UI (под мьютексом).
func (s *Service) viewsLocked(now time.Time) []CodeView {
	views := make([]CodeView, len(s.entries))
	for i, e := range s.entries {
		code, left, err := otp.Generate(e.Secret, now)
		if err != nil {
			code, left = "------", 0
		}
		views[i] = CodeView{
			Account:     Account{ID: i, Issuer: e.Issuer, Name: e.Name},
			Code:        code,
			SecondsLeft: left,
		}
	}
	return views
}

// ExportBackup — зашифрованный дамп всех записей отдельным паролем.
// Файл запрашивается системным диалогом «Сохранить как»; без диалога
// (адаптер не подключён) сохраняем в Документы — старое поведение.
func (s *Service) ExportBackup(password string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.open {
		return "", errors.New("vault is locked")
	}
	if len(password) < 8 {
		return "", errors.New("пароль резервной копии — минимум 8 символов")
	}

	data, err := vault.Encode(password, s.entries)
	if err != nil {
		return "", err
	}

	name := "coffer-backup-" + time.Now().Format("20060102-150405") + ".cofbak"
	path := ""
	if s.picker != nil {
		path, err = s.picker.SaveFile(name)
		if err != nil {
			return "", err
		}
		if path == "" {
			return "", nil // отменили диалог — не ошибка
		}
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir := filepath.Join(home, "Documents")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		path = filepath.Join(dir, name)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec // путь из диалога или UserHomeDir
		return "", fmt.Errorf("не удалось записать копию: %w", err)
	}
	return path, nil
}

// ImportBackup — читает резервную копию, выбранную системным диалогом,
// и добавляет записи, которых ещё нет. Дубликаты пропускаются.
func (s *Service) ImportBackup(password string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.open {
		return 0, errors.New("vault is locked")
	}
	if len(password) < 8 {
		return 0, errors.New("пароль резервной копии — минимум 8 символов")
	}
	if s.picker == nil {
		return 0, errors.New("выбор файла недоступен: адаптер диалогов не подключён")
	}
	path, err := s.picker.OpenFile()
	if err != nil {
		return 0, err
	}
	if path == "" {
		return 0, nil // отменили диалог
	}

	raw, err := os.ReadFile(path) //nolint:gosec // путь выбирает пользователь в диалоге
	if err != nil {
		return 0, fmt.Errorf("не удалось прочитать файл: %w", err)
	}
	imported, err := vault.Decode(password, raw)
	if err != nil {
		return 0, err
	}

	before := len(s.entries)
	for _, e := range imported {
		dup := slices.ContainsFunc(s.entries, func(x vault.Entry) bool {
			return x.Issuer == e.Issuer && x.Name == e.Name && x.Secret == e.Secret
		})
		if !dup {
			s.entries = append(s.entries, e)
		}
	}
	added := len(s.entries) - before
	if added == 0 {
		return 0, nil
	}
	if err := s.v.SaveWithKey(s.key, s.entries); err != nil {
		s.entries = s.entries[:before]
		return 0, fmt.Errorf("не удалось сохранить сейф: %w", err)
	}
	return added, nil
}

// FilePicker — абстракция системных диалогов выбора файла.
// Сервис не знает о Wails: тесты подсовывают фейк, main.go — реальный
// адаптер на диалогах Wails.
type FilePicker interface {
	SaveFile(defaultName string) (string, error) // "" = пользователь отменил
	OpenFile() (string, error)                   // "" = пользователь отменил
}

// SetFilePicker подключает реализацию диалогов (вызывается из main.go).
func (s *Service) SetFilePicker(fp FilePicker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.picker = fp
}
