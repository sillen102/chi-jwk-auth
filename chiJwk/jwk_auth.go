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
const DefaultJwkUri = "/protocol/openid-connect/certs"

// JwkAuthOptions is the struct for the jwk auth middleware.
type JwkAuthOptions struct {
    JwkSet                 jwk.Set
    oldJwkSet              jwk.Set
    Issuer                 string
    IssuerJwkUrl           string
    RenewKeys              bool
    RenewalInterval        time.Duration
    KeyRotationGracePeriod time.Duration
    Logger                 Logger
}

// NewJwkOptions creates a new jwk auth middleware.
func NewJwkOptions(issuer string) (*JwkAuthOptions, error) {
    jwksSet, err := jwk.Fetch(context.Background(), issuer+DefaultJwkUri)
    if err != nil {
        return nil, errors.New("could not fetch jwks key set")
    }

    return &JwkAuthOptions{
        JwkSet:                 jwksSet,
        oldJwkSet:              nil,
        Issuer:                 issuer,
        IssuerJwkUrl:           issuer + DefaultJwkUri,
        RenewKeys:              true,
        RenewalInterval:        10 * time.Minute,
        KeyRotationGracePeriod: 30 * time.Minute,
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

// WithRenewKeys sets the renew keys option that determines if the keys should be renewed
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

// AuthMiddleware is the middleware for authenticating requests.
func (options *JwkAuthOptions) AuthMiddleware() func(next http.Handler) http.Handler {
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
            token, err := jwt.Parse([]byte(tokenStr), jwt.WithKeySet(options.JwkSet), jwt.WithValidate(true))
            if err != nil && options.oldJwkSet != nil {
                // If validation with the new keys failed and there are old keys, try the old keys
                token, err = jwt.Parse([]byte(tokenStr), jwt.WithKeySet(options.oldJwkSet), jwt.WithValidate(true))
            }
            if err != nil {
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
            }

            // Check the issuer
            if token.Issuer() != options.Issuer {
                http.Error(w, "Invalid issuer", http.StatusUnauthorized)
                return
            }

            // Get claims
            claims, err := token.AsMap(r.Context())
            if err != nil {
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
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
func GetClaims(ctx context.Context, token any) error {
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
