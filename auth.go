package geoauth

import (
	"context"
	"net/http"
	"sync"
)

type Config struct {
	// Email is the user's email to log in.
	Email string
	// Password is the user's password.
	Password string
	// AuthURL is the resource server's authorization endpoint URL.
	AuthURL string
}

// PasswordCredentialsToken converts a resource owner email and password
// pair into a token.
func (c *Config) PasswordCredentialsToken(ctx context.Context) (*Token, error) {
	return retrieveToken(ctx, c)
}

// Client returns an HTTP client using the provided token.
// The token will auth-refresh as necessary. The underlying
// HTTP transport will be obtained using the provided context.
// The returned client and its Transport should not be modified.
func (c *Config) Client(ctx context.Context, t *Token) *http.Client {
	return NewClient(ctx, c.TokenSource(ctx, t))
}

// TokenSource returns a TokenSource that returns t until t expires,
// automatically refreshing it as necessary using the provided context.
func (c *Config) TokenSource(ctx context.Context, t *Token) TokenSource {
	tkr := &tokenRefresher{
		ctx:  ctx,
		conf: c,
	}
	return &reuseTokenSource{
		t:   t,
		new: tkr,
	}
}

// tokenRefresher is a TokenSource that makes HTTP requests to renew a token
type tokenRefresher struct {
	ctx  context.Context
	conf *Config
}

func (tf *tokenRefresher) Token() (*Token, error) {
	tk, err := retrieveToken(tf.ctx, tf.conf)
	if err != nil {
		return nil, err
	}
	return tk, err
}

// A TokenSource is anything that can return a token.
type TokenSource interface {
	// Token returns a token or an error.
	Token() (*Token, error)
}

// reuseTokenSource is a TokenSource that holds a single token in memory
// and validates its expiry before each call to retrieve it with Token.
// If it's expired, it will be auto-refreshed using the new TokenSource.
type reuseTokenSource struct {
	new TokenSource // called when t is expired.

	mu sync.Mutex
	t  *Token
}

// Token returns the current token if it's still valid, else will refresh
// the current token (using r.Context for HTTP client information)
// and return the new one.
func (s *reuseTokenSource) Token() (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.t.Valid() {
		return s.t, nil
	}
	t, err := s.new.Token()
	if err != nil {
		return nil, err
	}
	s.t = t
	return t, nil
}

// NewClient creates an *http.Client from a Context and TokenSource.
// The returned client is not valid beyond the lifetime of the context.
func NewClient(ctx context.Context, src TokenSource) *http.Client {
	if src == nil {
		return ContextClient(ctx)
	}
	return &http.Client{
		Transport: &Transport{
			Base:   ContextClient(ctx).Transport,
			Source: ReuseTokenSource(nil, src),
		},
	}
}

// ReuseTokenSource returns a TokenSource which repeatedly returns the
// same token as long as it's valid, starting with t.
// When its cached token is invalid, a new token is obtained from src.
func ReuseTokenSource(t *Token, src TokenSource) TokenSource {
	if rt, ok := src.(*reuseTokenSource); ok {
		if t == nil {
			return rt
		}
		src = rt.new
	}
	return &reuseTokenSource{
		t:   t,
		new: src,
	}
}
