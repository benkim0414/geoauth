package geoauth

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newConf(url string) *Config {
	return &Config{
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		AuthURL:      url,
	}
}

func TestConfigFromJSON(t *testing.T) {
	var jsonKey = []byte(`{
		"client_id": "CLIENT_ID",
		"client_secret": "CLIENT_SECRET"
	}`)

	conf, err := ConfigFromJSON(jsonKey)
	if err != nil {
		t.Error(err)
	}
	if got, want := conf.ClientID, "CLIENT_ID"; got != want {
		t.Errorf("ClientID = %q, want %q", got, want)
	}
	if got, want := conf.ClientSecret, "CLIENT_SECRET"; got != want {
		t.Errorf("ClientSecret = %q, want %q", got, want)
	}
}

func TestPasswordCredentialsTokenRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		headerContentType := r.Header.Get("Content-Type")
		expected := "application/json"
		if headerContentType != expected {
			t.Errorf("Content-Type header = %q; want %q", headerContentType, expected)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}
		expected = `{"user": {"email": "CLIENT_ID", "password": "CLIENT_SECRET"}}`
		if string(body) != expected {
			t.Errorf("res.Body = %q; wnat %q", string(body), expected)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{
			"authenticationToken": {
				"token": "7CbSGwAngmtTWR2kEds9KN0yZIxLJYBj",
				"expiresAt": %q
			}
		}`, time.Now().Add(time.Hour).Format("2006-01-02T15:04:05.999999999"))))
	}))
	defer ts.Close()
	conf := newConf(ts.URL)
	tok, err := conf.PasswordCredentialsToken(context.Background())
	if err != nil {
		t.Error(err)
	}
	if !tok.Valid() {
		t.Fatalf("Token invalid. Got: %#v", tok)
	}
	expected := "7CbSGwAngmtTWR2kEds9KN0yZIxLJYBj"
	if tok.AccessToken != expected {
		t.Errorf("AccessToken = %q; want %q", tok.AccessToken, expected)
	}
}

func TestTokenRefreshRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() == "/somethingelse" {
			return
		}
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/json" {
			t.Errorf("Unexpected Content-Type header, %v is found.", headerContentType)
		}
		body, _ := ioutil.ReadAll(r.Body)
		if string(body) != `{"user": {"email": "CLIENT_ID", "password": "CLIENT_SECRET"}}` {
			t.Errorf("Unexpected refresh request payload, %v is found.", string(body))
		}
	}))
	defer ts.Close()
	conf := newConf(ts.URL)
	c := conf.Client(context.Background(), &Token{})
	c.Get(ts.URL + "/somethingelse")
}

func TestTokenRetrieveError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"statusMessage": "Invalid email or password"}`))
	}))
	defer ts.Close()
	conf := newConf(ts.URL)
	_, err := conf.PasswordCredentialsToken(context.Background())
	if err == nil {
		t.Fatalf("got no error, expected one")
	}
	_, ok := err.(*RetrieveError)
	if !ok {
		t.Fatalf("got %T error, expected *RetrieveError", err)
	}

	expected := fmt.Sprintf("cannot fetch token: %v\nResponse: %s", "400 Bad Request", `{"statusMessage": "Invalid email or password"}`)
	if errStr := err.Error(); errStr != expected {
		t.Fatalf("got %#v, expected %#v", errStr, expected)
	}
}

func TestConfigClientWithToken(t *testing.T) {
	tok := &Token{
		AccessToken: "ACCESS_TOKEN",
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Authorization"), fmt.Sprintf("token %s", tok.AccessToken); got != want {
			t.Errorf("Authorization header = %q; want %q", got, want)
		}
		return
	}))
	defer ts.Close()
	conf := newConf(ts.URL)

	c := conf.Client(context.Background(), tok)
	req, err := http.NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Error(err)
	}
	_, err = c.Do(req)
	if err != nil {
		t.Error(err)
	}
}
