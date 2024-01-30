package chiJwk

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "net/http"
    "strings"
    "time"

    "github.com/lestrrat-go/jwx/v2/jwk"
    "github.com/lestrrat-go/jwx/v2/jwt"
    "github.com/mitchellh/mapstructure"
)

const JwtTokenKey = "jwt-token"

// JwkAuthOptions is the struct for the jwk auth middleware.
type JwkAuthOptions struct {
    JwkSet                 jwk.Set
    oldJwkSet              jwk.Set
    Issuer                 string
    IssuerJwkUrl           string
    Filter                 Filter
    RenewKeys              bool
    RenewalInterval        time.Duration
    KeyRotationGracePeriod time.Duration
    Logger                 Logger
    CreateToken            func(claims map[string]interface{}) (Token, error)
}

type Token interface {
    Roles() []string
    Scopes() []string
}

type Filter interface {
    Roles() []string
    Scopes() []string
}

type DefaultFilter struct {
    FilterRoles  []string
    FilterScopes []string
}

func (f DefaultFilter) Roles() []string {
    return f.FilterRoles
}

func (f DefaultFilter) Scopes() []string {
    return f.FilterScopes
}

// NewJwkOptions creates a new jwk auth middleware.
func NewJwkOptions(issuer string, jwksUrl string) (*JwkAuthOptions, error) {
    jwksSet, err := jwk.Fetch(context.Background(), jwksUrl)
    if err != nil {
        return nil, errors.New("could not fetch jwks key set")
    }

    return &JwkAuthOptions{
        JwkSet:                 jwksSet,
        oldJwkSet:              nil,
        Issuer:                 issuer,
        IssuerJwkUrl:           jwksUrl,
        Filter:                 DefaultFilter{FilterRoles: make([]string, 0), FilterScopes: make([]string, 0)},
        RenewKeys:              true,
        RenewalInterval:        10 * time.Minute,
        KeyRotationGracePeriod: 30 * time.Minute,
        CreateToken:            CreateTokenFromClaims[Token],
    }, nil
}

// WithIssuer sets the issuer option that determines the issuer of the tokens.
func (options *JwkAuthOptions) WithIssuer(issuer string) {
    options.Issuer = issuer
}

// WithIssuerJwkUrl sets the issuer JWK URL option that determines where the JWK Set should
// be fetched from.
func (options *JwkAuthOptions) WithIssuerJwkUrl(issuerJwkUrl string) {
    options.IssuerJwkUrl = issuerJwkUrl
}

// WithFilter sets the filter option that determines the roles and scopes that are required
// for the token.
func (options *JwkAuthOptions) WithFilter(filter Filter) {
    options.Filter = filter
}

// WithRenewKeys sets the option for key renewal that determines if the keys should be renewed
// at regular intervals.
func (options *JwkAuthOptions) WithRenewKeys(renewKeys bool) {
    options.RenewKeys = renewKeys
}

// WithRenewalInterval sets the renewal interval option that determines how often the keys
// should be renewed.
func (options *JwkAuthOptions) WithRenewalInterval(renewalInterval time.Duration) {
    options.RenewalInterval = renewalInterval
}

// WithKeyRotationGracePeriod sets the key rotation grace period option that determines how
// long the old keys should be kept after the new keys have been fetched.
func (options *JwkAuthOptions) WithKeyRotationGracePeriod(keyRotationGracePeriod time.Duration) {
    options.KeyRotationGracePeriod = keyRotationGracePeriod
}

// WithLogger sets the logger option that determines how the library logs messages.
func (options *JwkAuthOptions) WithLogger(logger Logger) {
    options.Logger = logger
}

// WithCreateToken sets the create token option that determines how the token is created.
func (options *JwkAuthOptions) WithCreateToken(createToken func(claims map[string]interface{}) (Token, error)) {
    options.CreateToken = createToken
}

// AuthMiddleware is the middleware for authenticating requests.
func (options *JwkAuthOptions) AuthMiddleware(filter ...Filter) func(next http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        if options.RenewKeys {
            options.startKeyRenewal()
        }

        fn := func(w http.ResponseWriter, r *http.Request) {
            // Get the Authorization header
            authHeader := r.Header.Get("Authorization")
            if authHeader == "" {
                http.Error(w, "Authorization header required", http.StatusUnauthorized)
                return
            }

            // Check if the Authorization header starts with "Bearer "
            if !strings.HasPrefix(authHeader, "Bearer ") {
                http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
                return
            }

            // Extract the token from the Authorization header
            tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

            // Parse and verify the token
            jwtToken, err := jwt.Parse([]byte(tokenStr), jwt.WithKeySet(options.JwkSet), jwt.WithValidate(true))
            if err != nil && options.oldJwkSet != nil {
                // If validation with the new keys failed and there are old keys, try the old keys
                jwtToken, err = jwt.Parse([]byte(tokenStr), jwt.WithKeySet(options.oldJwkSet), jwt.WithValidate(true))
            }
            if err != nil {
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
            }

            // Check the issuer
            if jwtToken.Issuer() != options.Issuer {
                http.Error(w, "Invalid issuer", http.StatusUnauthorized)
                return
            }

            // Get claims
            claims, err := jwtToken.AsMap(r.Context())
            if err != nil {
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
            }

            // Create token instance
            token, err := options.CreateToken(claims)
            if err != nil {
                http.Error(w, "Invalid token type", http.StatusUnauthorized)
                return
            }

            // Check if the token passes filters
            for _, f := range filter {
                if f == nil {
                    continue
                }

                if !TokenHasRequiredRoles(token.Roles(), f.Roles()) {
                    http.Error(w, "Unauthorized", http.StatusUnauthorized)
                    return
                }

                if !TokenHasRequiredScopes(token.Scopes(), f.Scopes()) {
                    http.Error(w, "Unauthorized", http.StatusUnauthorized)
                    return
                }
            }

            // Add claims to context
            ctx := context.WithValue(r.Context(), JwtTokenKey, claims)

            // Call the next handler
            next.ServeHTTP(w, r.WithContext(ctx))
        }

        return http.HandlerFunc(fn)
    }
}

// GetClaims extracts the token claims from the context into the provided object.
func GetClaims(ctx context.Context, token Token) error {
    claims, ok := ctx.Value(JwtTokenKey).(map[string]interface{})
    if !ok {
        return errors.New("could not get token from context")
    }

    err := mapstructure.Decode(claims, token)
    if err != nil {
        return fmt.Errorf("failed to decode token: %w", err)
    }

    return nil
}

// CreateTokenFromClaims create a token from claims.
// The token must implement the Token interface and have mapstructure tags.
func CreateTokenFromClaims[T Token](claims map[string]interface{}) (Token, error) {
    var token T
    err := mapstructure.Decode(claims, &token)
    if err != nil {
        return nil, err
    }
    return token, nil
}

// TokenHasRequiredRoles checks if the token has the required scopes.
func TokenHasRequiredRoles(tokenRoles []string, requiredRoles []string) bool {
    if requiredRoles == nil || len(requiredRoles) == 0 {
        return true
    }

    // Create a map for quick lookup of token roles
    tokenRolesMap := make(map[string]bool)
    for _, role := range tokenRoles {
        tokenRolesMap[role] = true
    }

    // Check if all required roles are in the token roles
    for _, requiredRole := range requiredRoles {
        if _, ok := tokenRolesMap[requiredRole]; !ok {
            return false
        }
    }

    return true
}

// TokenHasRequiredScopes checks if the token has the required scopes.
func TokenHasRequiredScopes(tokenScopes []string, requiredScopes []string) bool {
    // Create a map for quick lookup of token scopes
    tokenScopesMap := make(map[string]bool)
    for _, scope := range tokenScopes {
        tokenScopesMap[scope] = true
    }

    // Check if all required scopes are in the token scopes
    for _, requiredScope := range requiredScopes {
        if _, ok := tokenScopesMap[requiredScope]; !ok {
            return false
        }
    }

    return true
}

// startKeyRenewal starts a ticker that fetches the JWK Set at regular intervals.
func (options *JwkAuthOptions) startKeyRenewal() {
    if !options.RenewKeys {
        return
    }

    ticker := time.NewTicker(options.RenewalInterval)
    go func() {
        for range ticker.C {
            // Fetch the new JWK Set
            options.Logger.Debug("Fetching JWK Set")
            newJwkSet, err := jwk.Fetch(context.Background(), options.IssuerJwkUrl)
            if err != nil {
                options.Logger.Error(err, "Error fetching JWK Set")
                continue
            }

            // Convert the current and new JWK Sets to JSON
            options.Logger.Debug("Marshaling JWK Sets")
            currentJwkSetJson, err := json.Marshal(options.JwkSet)
            if err != nil {
                options.Logger.Error(err, "Error marshaling current JWK Set")
                continue
            }
            newJwkSetJson, err := json.Marshal(newJwkSet)
            if err != nil {
                options.Logger.Error(err, "Error marshaling new JWK Set")
                continue
            }

            // If the JWK Sets are the same, skip the update
            if string(currentJwkSetJson) == string(newJwkSetJson) {
                options.Logger.Debug("JWK Set has not changed")
                continue
            }

            // Keep the old JWK Set and update the current one
            options.Logger.Debug("Updating JWK Set")
            options.oldJwkSet = options.JwkSet
            options.JwkSet = newJwkSet

            // Start a timer for the grace period
            time.AfterFunc(options.KeyRotationGracePeriod, func() {
                // After the grace period, discard the old JWK Set
                options.Logger.Debug("Discarding old JWK Set")
                options.oldJwkSet = nil
            })
        }
    }()
}
