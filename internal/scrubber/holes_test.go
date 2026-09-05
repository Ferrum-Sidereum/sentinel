package scrubber

import (
	"encoding/base64"
	"strings"
	"testing"
)

func hasType(fs []Finding, typ string) bool {
	for _, f := range fs {
		if f.Type == typ {
			return true
		}
	}
	return false
}

func TestIBANValid(t *testing.T) {
	if !validIBAN("DE89370400440532013000") {
		t.Fatal("valid IBAN rejected")
	}
	if validIBAN("DE89370400440532013001") {
		t.Fatal("invalid IBAN accepted")
	}
	if !hasType(Scan("iban DE89370400440532013000", nil, nil), "IBAN") {
		t.Fatal("IBAN not detected in Scan")
	}
}

func TestOMS(t *testing.T) {
	if !validOMS("1234567890123456") {
		t.Fatal("valid OMS rejected")
	}
	if validOMS("0000000000000000") {
		t.Fatal("uniform OMS accepted")
	}
	if !hasType(Scan("полис 1234567890123456", nil, nil), "OMS") {
		t.Fatal("OMS not detected in Scan")
	}
}

func TestEntropyStrengthened(t *testing.T) {
	fs := Scan("api_key = Gh7xQ9mK2vB4nR8tY5wZ1aD6eF3gH0jK", nil, nil)
	if !hasType(fs, "HIGH_ENTROPY") {
		t.Fatal("entropy token near secret word not detected")
	}
}

func TestNameDict(t *testing.T) {
	fs := Scan("клиент Иван Петров обратился", nil, nil)
	if !hasType(fs, "PERSON_NAME") {
		t.Fatal("dict name not detected")
	}
}

func TestCustomPatterns(t *testing.T) {
	cp := CompileCustomPatterns(map[string]string{"EMP_ID": `EMP-\d{6}`})
	fs := ScanCustom("badge EMP-123456", nil, nil, cp)
	if !hasType(fs, "EMP_ID") {
		t.Fatal("custom pattern not detected")
	}
}

func TestBase64Decode(t *testing.T) {
	raw := "contact ivan.petrov@example.com please"
	enc := base64.StdEncoding.EncodeToString([]byte(raw))
	fs := Scan("blob "+enc, nil, nil)
	if len(fs) == 0 {
		t.Fatal("base64 payload not detected")
	}
}

func TestJSONDepthLimits(t *testing.T) {
	deep := strings.Repeat(`{"a":`, 40) + "1" + strings.Repeat("}", 40)
	if err := CheckJSONDepth([]byte(deep)); err == nil {
		t.Fatal("deep JSON not rejected")
	}
	if err := CheckJSONDepth([]byte(`{"a":1}`)); err != nil {
		t.Fatalf("shallow JSON rejected: %v", err)
	}
	big := make([]byte, maxScanBytes+1)
	if err := CheckJSONDepth(big); err == nil {
		t.Fatal("oversize payload not rejected")
	}
}
