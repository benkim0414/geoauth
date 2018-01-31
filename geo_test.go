package geoauth

import "testing"

var jsonKey = []byte(`{
	"email": "EMAIL",
	"password": "PASSWORD"
}`)

func TestConfigFromJSON(t *testing.T) {
	conf, err := ConfigFromJSON(jsonKey)
	if err != nil {
		t.Error(err)
	}
	if got, want := conf.Email, "EMAIL"; got != want {
		t.Errorf("Email = %q, want %q", got, want)
	}
	if got, want := conf.Password, "PASSWORD"; got != want {
		t.Errorf("Password = %q, want %q", got, want)
	}
	if got, want := conf.AuthURL, GEOAuthURL; got != want {
		t.Errorf("AuthURL = %q; want %q", got, want)
	}
}
