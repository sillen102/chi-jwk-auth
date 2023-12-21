package chiJwk

import (
    "context"
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
    JwkSet          jwk.Set
    Issuer          string
    RenewKeys       bool
    RenewalInterval time.Duration
}

// NewJwkOptions creates a new jwk auth middleware.
func NewJwkOptions(issuer string) (*JwkAuthOptions, error) {
    jwksSet, err := jwk.Fetch(context.Background(), issuer+"/protocol/openid-connect/certs")
    if err != nil {
        return nil, errors.New("could not fetch jwks key set")
    }

    return &JwkAuthOptions{
        JwkSet:    jwksSet,
        Issuer:    issuer,
        RenewKeys: false,
    }, nil
}

// AuthMiddleware is the middleware for authenticating requests.
func (options *JwkAuthOptions) AuthMiddleware() func(next http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
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
            if err != nil {
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
            }

            // Check the issuer
            if token.Issuer() != options.Issuer {
                http.Error(w, "Invalid issuer", http.StatusUnauthorized)
                return
            }

            // Add token to context
            ctx := context.WithValue(r.Context(), JwtTokenKey, token)

            // Call the next handler
            next.ServeHTTP(w, r.WithContext(ctx))
        }
        return http.HandlerFunc(fn)
    }
}

// ExtractToken extracts a token from the context into the provided object.
func ExtractToken(ctx context.Context, token any) error {
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
