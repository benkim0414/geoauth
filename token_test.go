package geoauth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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

func TestRetrieveTokenWithContexts(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{
			"authenticationToken": {
				"token": "ACCESS_TOKEN",
				"expiresAt": "2006-01-02T15:04:05Z"
			}
		}`)
	}))
	defer ts.Close()

	conf := &Config{
		AuthURL: ts.URL,
	}
	_, err := retrieveToken(context.Background(), conf)
	if err != nil {
		t.Errorf("retrieveToken (with background context) = %v; want no error", err)
	}

	retrieved := make(chan struct{})
	cancellingts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-retrieved
	}))
	defer cancellingts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = retrieveToken(ctx, conf)
	close(retrieved)
	if err == nil {
		t.Errorf("retrieveToken (with cancelled context) = nil; want error)")
	}
}
