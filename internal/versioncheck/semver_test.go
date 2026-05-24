package versioncheck

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.3.0", "0.4.0", -1},
		{"0.4.0", "0.4.0", 0},
		{"0.5.0", "0.4.9", 1},
		{"v0.4.0", "0.4.0", 0},
		{"0.4.0-beta", "0.4.0", 0},
	}
	for _, tc := range cases {
		if got := Compare(tc.a, tc.b); got != tc.want {
			t.Fatalf("Compare(%q,%q)=%d want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
