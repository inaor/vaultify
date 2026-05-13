package session

import "testing"

// Session ID format tests.

func TestIsValidID(t *testing.T) {
	id := NewID()
	if !IsValidID(id) {
		t.Fatalf("NewID() should always be valid: %q", id)
	}
	cases := []struct {
		id   string
		want bool
	}{
		{"", false},
		{"abc", false},
		{"ABCDEF0123456789", false},
		{"../escape", false},
		{"0123456789abcdef", true},
	}
	for _, tc := range cases {
		if got := IsValidID(tc.id); got != tc.want {
			t.Errorf("IsValidID(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
}
