package termsecret

import (
	"strings"
	"testing"
)

func TestStripOneNewline(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"abc\n", "abc"},
		{"abc\r\n", "abc"},
		{"abc", "abc"},
		{"abc\n\n", "abc\n"},
		{"abc ", "abc "},
		{" a=b c \n", " a=b c "},
	}
	for _, c := range cases {
		got := string(stripOneNewline([]byte(c.in)))
		if got != c.want {
			t.Errorf("stripOneNewline(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestReadPipePreservesSpacesAndEquals(t *testing.T) {
	got, err := readPipe(strings.NewReader(" a=b c \n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != " a=b c " {
		t.Fatalf("got %q", got)
	}
}

func TestReadPipeEmpty(t *testing.T) {
	if _, err := readPipe(strings.NewReader("\n")); err != ErrEmpty {
		t.Fatalf("want ErrEmpty, got %v", err)
	}
}
