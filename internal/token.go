package internal

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

var (
	// ErrNoToken is returned if a request is successful but the body
	// does not contain an authentication token.
	ErrNoToken = errors.New("authentication server did not include a token in the response")
)

// Token represents the credentials used to authorize the requests
// to access protected resources on GEO backend.
type Token struct {
	// AccessToken is the token that authoizes and authenticates
	// the requests.
	AccessToken string

	// Expiry is the optional expiration time of the access token.
	Expiry time.Time
}

// tokenJSON is the struct representing the HTTP response from GEO
// returning a token in JSON form.
type tokenJSON struct {
	ID        string `json:"_id"`
	Type      string `json:"_type"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
	UserID    string `json:"userId"`
}

func (t *tokenJSON) expiry() (time.Time, error) {
	const layout = "2006-01-02T15:04:05.999999999"
	return time.Parse(layout, t.ExpiresAt)
}

func RetrieveToken(ctx context.Context, email, password, authURL string) (*Token, error) {
	payload := fmt.Sprintf(`{"user": {"email": %q, "password": %q}}`, email, password)
	req, err := http.NewRequest(http.MethodPost, authURL, strings.NewReader(payload))
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

type RetrieveError struct {
	Response *http.Response
	Body     []byte
}

func (r *RetrieveError) Error() string {
	return fmt.Sprintf("cannot fetch token %v\nResponse: %s", r.Response.Status, r.Body)
}
