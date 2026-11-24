package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestVault(t *testing.T) *Vault {
	t.Helper()
	return New(filepath.Join(t.TempDir(), "test.cof"))
}

func sampleEntries() []Entry {
	return []Entry{
		{
			Name: "user@example.com", Issuer: "GitHub",
			Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", CreatedAt: time.Now(),
		},
	}
}

// Круговорот: сохранили → открыли тем же паролем → данные совпали.
func TestRoundtrip(t *testing.T) {
	v := newTestVault(t)
	want := sampleEntries()

	if err := v.Save("correct horse", want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := v.Open("correct horse")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(got) != len(want) || got[0].Secret != want[0].Secret || got[0].Issuer != want[0].Issuer {
		t.Errorf("roundtrip mismatch: %+v != %+v", got, want)
	}
}

// Неверный пароль обязан вернуть ErrWrongPassword, а не мусор.
func TestWrongPassword(t *testing.T) {
	v := newTestVault(t)
	if err := v.Save("correct horse", sampleEntries()); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Open("battery staple"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("want ErrWrongPassword, got %v", err)
	}
}

// Порча одного байта шифротекста = отказ расшифровки (аутентификация GCM).
func TestTamperDetection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tamper.cof")
	tv := New(path)
	if err := tv.Save("pw", sampleEntries()); err != nil {
		t.Fatal(err)
	}

	// Читаем файл, переворачиваем последний байт шифротекста и пишем обратно.
	// В тесте прямая запись безопасна: атомарность важна для живого сейфа,
	// здесь мы намеренно имитируем «испорченный диск».
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xFF
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// Испорченный сейф не должен расшифроваться — причём ошибкой
	// именно «неверный пароль»: GCM не отличает подделку от чужого ключа.
	if _, err := tv.Open("pw"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("want ErrWrongPassword, got %v", err)
	}
}

// Пустой сейф сохранять запрещено: это защита от случайной перезаписи
// валидного сейфа пустым (сценарий бага в UI).
func TestSaveRefusesEmpty(t *testing.T) {
	v := newTestVault(t)
	if err := v.Save("pw", nil); err == nil {
		t.Error("empty vault must not be saved")
	}
}

// Круговорот через РАЗНЫЕ экземпляры: writer сохраняет, reader
// открывает. У reader'а нет кэша соли — она читается из файла,
// ровно как при запуске нового процесса. Именно такой тест поймал
// бы баг «nonce вместо соли» на этапе, а не в бою.
func TestRoundtripFreshInstance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cross.cof")

	writer := New(path)
	if err := writer.Save("pw", sampleEntries()); err != nil {
		t.Fatalf("save: %v", err)
	}

	reader := New(path) // новый экземпляр — как новый процесс
	got, err := reader.Open("pw")
	if err != nil {
		t.Fatalf("fresh instance open: %v", err)
	}
	if len(got) != 1 || got[0].Secret != sampleEntries()[0].Secret {
		t.Errorf("mismatch: %+v", got)
	}
}

func TestEncodeDecodeRoundtrip(t *testing.T) {
	data, err := Encode("backup-pw", sampleEntries())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := Decode("backup-pw", data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].Secret != sampleEntries()[0].Secret {
		t.Errorf("mismatch: %+v", got)
	}
	if _, err := Decode("wrong", data); err != ErrWrongPassword {
		t.Errorf("want ErrWrongPassword, got %v", err)
	}
}
