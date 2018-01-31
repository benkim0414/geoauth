package geoauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/context/ctxhttp"
)

// expiryDelta determines how earlier a token should be considered
// expired then its actual expiration time. It is used to avoid late
// expirations due to client-server time mismatches.
const expiryDelta = 10 * time.Second

var (
	// ErrNoToken is returned if a request is successful but the body
	// does not contain an authorization token.
	ErrNoToken = errors.New("authorization server did not include a token in the response")
)

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

// tokenJSON is the struct representing the HTTP response from GEO
// returning a token in JSON form.
type tokenJSON struct {
	//	ID        string `json:"_id"`
	//	Type      string `json:"_type"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
	//	UserID    string `json:"userId"`
}

func (t *tokenJSON) expiry() (time.Time, error) {
	return time.Parse(time.RFC3339, t.ExpiresAt)
}

// retrieveToken takes a *Config and uses that to retrieve an Token.
func retrieveToken(ctx context.Context, c *Config) (*Token, error) {
	user := fmt.Sprintf(`{"user": {"email": %q, "password": %q}}`, c.Email, c.Password)
	req, err := http.NewRequest(http.MethodPost, c.AuthURL, strings.NewReader(user))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	r, err := ctxhttp.Do(ctx, ContextClient(ctx), req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, &RetrieveError{
			Response: r,
			Body:     body,
		}
	}

	var authToken struct {
		Tok tokenJSON `json:"authenticationToken"`
	}
	if err = json.Unmarshal(body, &authToken); err != nil {
		return nil, err
	}
	token := &Token{
		AccessToken: authToken.Tok.Token,
	}
	token.Expiry, err = authToken.Tok.expiry()
	if err != nil {
		return nil, err
	}
	// Don't overwrite `AccessToken` with an empty value
	// if this was a token refreshing request.
	if token.AccessToken == "" {
		return token, ErrNoToken
	}
	return token, nil
}

// RetrieveError is the error returned when the token endpoint returns a
// non-2xx HTTP status code.
type RetrieveError struct {
	Response *http.Response
	Body     []byte
}

func (r *RetrieveError) Error() string {
	return fmt.Sprintf("cannot fetch token %v\nResponse: %s", r.Response.Status, r.Body)
}
