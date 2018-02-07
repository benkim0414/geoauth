package geoauth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/benkim0414/geoauth/internal"
)

// expiryDelta determines how earlier a token should be considered
// expired then its actual expiration time. It is used to avoid late
// expirations due to client-server time mismatches.
const expiryDelta = 10 * time.Second

// Token represents the credentials used to authorize the requests
// to access protected resources on GEO backend.
type Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string

	// Expiry is the optional expiration time of the access token.
	Expiry time.Time
}

// SetAuthHeader sets the Authorization header to r using the access
// token in t.
func (t *Token) SetAuthHeader(r *http.Request) {
	r.Header.Set("Authorization", "token "+t.AccessToken)
}

// expired reports whether the token is expired.
func (t *Token) expired() bool {
	if t.Expiry.IsZero() {
		return false
	}
	return t.Expiry.Round(0).Add(-expiryDelta).Before(time.Now())
}

// Valid reporets whether t is non-nil, has an AccessToken, and is not expired.
func (t *Token) Valid() bool {
	return t != nil && t.AccessToken != "" && !t.expired()
}

// tokenFromInternal maps an *internal.Token struct into a *Token struct.
func tokenFromInternal(t *internal.Token) *Token {
	if t == nil {
		return nil
	}
	return &Token{
		AccessToken: t.AccessToken,
		Expiry:      t.Expiry,
	}
}

// retrieveToken takes a *Config and uses that to retrieve an *internal.Token.
// This token is then mapped from *internal.Token into an *geoauth.Token
// which is returned along with an error.
func retrieveToken(ctx context.Context, c *Config) (*Token, error) {
	tk, err := internal.RetrieveToken(ctx, c.ClientID, c.ClientSecret, c.AuthURL)
	if err != nil {
		if rErr, ok := err.(*internal.RetrieveError); ok {
			return nil, (*RetrieveError)(rErr)
		}
		return nil, err
	}
	return tokenFromInternal(tk), nil
}

// RetrieveError is the error returned when the token endpoint returns a
// non-2xx HTTP status code.
type RetrieveError struct {
	Response *http.Response
	// Body is the body that was consumed by reading Response.Body.
	// It may be truncated.
	Body []byte
}

func (r *RetrieveError) Error() string {
	return fmt.Sprintf("cannot fetch token %v\nResponse: %s", r.Response.Status, r.Body)
}
