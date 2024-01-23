package keycloak

import (
    "strings"
    "time"

    "github.com/lestrrat-go/jwx/v2/jwt"
    "github.com/mitchellh/mapstructure"

    "github.com/sillen102/chi-jwk-auth/chiJwk"
)

// JwtToken is the struct for the token claims
type JwtToken struct {
    UserID         string      `mapstructure:"sub"`
    Username       string      `mapstructure:"preferred_username"`
    FirstName      string      `mapstructure:"given_name"`
    LastName       string      `mapstructure:"family_name"`
    Email          string      `mapstructure:"email"`
    EmailVerified  bool        `mapstructure:"email_verified"`
    RealmAccess    RealmAccess `mapstructure:"realm_access"`
    Audience       []string    `mapstructure:"aud"`
    Scope          string      `mapstructure:"scope"`
    IssuedAt       time.Time   `mapstructure:"iat"`
    ExpiresAt      time.Time   `mapstructure:"exp"`
    AllowedOrigins []string    `mapstructure:"allowed-origins"`
}

type RealmAccess struct {
    Roles []string `mapstructure:"tokenRoles"`
}

// CreateToken specifies how the token should be mapped from the claims.
func (t *JwtToken) CreateToken() func(*jwt.Token, map[string]interface{}) (chiJwk.Token, error) {
    return func(token *jwt.Token, claims map[string]interface{}) (chiJwk.Token, error) {
        var err error
        err = mapstructure.Decode(claims, &t)
        if err != nil {
            return nil, err
        }
        return t, nil
    }
}

// Issuer returns the issuer of the token.
func (t *JwtToken) Issuer() string {
    return t.Issuer()
}

// Roles returns the roles of the token.
func (t *JwtToken) Roles() []string {
    return t.RealmAccess.Roles
}

// Scopes returns the scopes of the token.
func (t *JwtToken) Scopes() []string {
    return strings.Split(t.Scope, " ")
}
