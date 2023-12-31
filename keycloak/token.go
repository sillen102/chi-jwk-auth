package keycloak

import (
    "time"
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
    Roles []string `mapstructure:"roles"`
}
