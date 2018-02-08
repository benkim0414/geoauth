package geoauth

import (
	"testing"
	"time"
)

func TestTokenExpiry(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name string
		tok  *Token
		want bool
	}{
		{name: "12 seconds", tok: &Token{Expiry: now.Add(12 * time.Second)}, want: false},
		{name: "10 seconds", tok: &Token{Expiry: now.Add(expiryDelta)}, want: true},
		{name: "-1 hour", tok: &Token{Expiry: now.Add(-1 * time.Hour)}, want: true},
	}
	for _, tt := range tests {
		if got, want := tt.tok.expired(), tt.want; got != want {
			t.Errorf("expired (%q) = %v, want %v", tt.name, got, want)
		}
	}
}
