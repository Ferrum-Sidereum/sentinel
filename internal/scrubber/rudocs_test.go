package scrubber

import "testing"

func TestSNILSValid(t *testing.T) {
	// digits 112233141: sum=82, check=82
	f := Scan("снис 112-233-141 82", nil, nil)
	found := false
	for _, x := range f {
		if x.Type == "SNILS" {
			found = true
		}
	}
	if !found {
		t.Fatalf("SNILS not detected: %v", f)
	}
}

func TestSNILSInvalid(t *testing.T) {
	f := Scan("112-233-141 00", nil, nil)
	for _, x := range f {
		if x.Type == "SNILS" {
			t.Fatalf("invalid SNILS detected: %v", f)
		}
	}
}

func TestINN12Valid(t *testing.T) {
	// valid FL INN example: 500100732259
	if !validINN12("500100732259") {
		t.Fatal("valid INN12 rejected")
	}
	f := Scan("инн 500100732259", nil, nil)
	found := false
	for _, x := range f {
		if x.Type == "INN_FL" {
			found = true
		}
	}
	if !found {
		t.Fatalf("INN_FL not detected: %v", f)
	}
}

func TestINN12Invalid(t *testing.T) {
	if validINN12("500100732250") {
		t.Fatal("invalid INN12 accepted")
	}
}

func TestPassportRU(t *testing.T) {
	f := Scan("паспорт 4510 №123456", nil, nil)
	found := false
	for _, x := range f {
		if x.Type == "PASSPORT_RU" {
			found = true
		}
	}
	if !found {
		t.Fatalf("PASSPORT_RU not detected: %v", f)
	}
}
