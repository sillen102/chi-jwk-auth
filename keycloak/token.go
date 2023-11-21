package keycloak

// Token is the struct for the token claims
type Token struct {
    UserID        string      `mapstructure:"sub"`
    FirstName     string      `mapstructure:"given_name"`
    LastName      string      `mapstructure:"family_name"`
    Email         string      `mapstructure:"email"`
    EmailVerified bool        `mapstructure:"email_verified"`
    RealmAccess   RealmAccess `mapstructure:"realm_access"`
}

type RealmAccess struct {
    Roles []string `mapstructure:"roles"`
}
