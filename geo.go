package geoauth

import "encoding/json"

const GEOAuthURL = "https://api.geocreation.com.au/session/login"

// ConfigFromJSON uses a geo_credentials.json file to construct a config.
func ConfigFromJSON(jsonKey []byte) (*Config, error) {
	var cred struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(jsonKey, &cred); err != nil {
		return nil, err
	}
	return &Config{
		Email:    cred.Email,
		Password: cred.Password,
		AuthURL:  GEOAuthURL,
	}, nil
}
