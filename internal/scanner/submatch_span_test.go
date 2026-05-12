package scanner

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestSubmatchSpanForHash_contextKey(t *testing.T) {
	val := "shodanSecretValue12345678"
	line := `SHODAN_API_KEY = "` + val + `" # comment`
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(val)))
	start, end, ok := SubmatchSpanForHash(line, "SHODAN_API_KEY", want)
	if !ok {
		t.Fatal("expected match for context-only pattern_id")
	}
	got := line[start:end]
	if got != val {
		t.Fatalf("substring = %q want %q", got, val)
	}
}

func TestSubmatchSpanForHash_cataloguePattern(t *testing.T) {
	val := "AKIAIOSFODNN7EXAMPLE"
	line := `export AWS_ACCESS_KEY_ID=` + val
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(val)))
	start, end, ok := SubmatchSpanForHash(line, "aws_access_key_id", want)
	if !ok {
		t.Fatal("expected catalogue regex match")
	}
	if line[start:end] != val {
		t.Fatalf("got %q", line[start:end])
	}
}

func TestSubmatchSpanForHash_wrongHash(t *testing.T) {
	line := `OTHER_KEY = "nope12345678901234"`
	_, _, ok := SubmatchSpanForHash(line, "OTHER_KEY", "deadbeef")
	if ok {
		t.Fatal("expected no match")
	}
}
