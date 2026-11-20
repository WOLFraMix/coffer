package otp

import (
	"testing"
	"time"
)

// Векторы из RFC 6238, Appendix B (SHA1, 6 цифр, T0=0, шаг 30с).
// Секрет "12345678901234567890" в Base32.
func TestGenerate_RFC6238Vectors(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}

	for _, c := range cases {
		got, _, err := Generate(secret, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("unix=%d: %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("unix=%d: got %s, want %s", c.unix, got, c.want)
		}
	}
}

func TestGenerate_ToleratesSpacesAndCase(t *testing.T) {
	a, _, err := Generate("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := Generate("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Unix(59, 0))
	if a != b {
		t.Errorf("normalization failed: %s != %s", a, b)
	}
}
