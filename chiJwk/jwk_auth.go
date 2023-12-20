package chiJwk

import (
    "context"
    "errors"
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
    Verifier        TokenVerifier
    RenewKeys       bool
    RenewalInterval time.Duration
}

// TokenVerifier is the interface for a verifier,
// you can use the GenericTokenVerifier or create your own implementation (useful in testing).
type TokenVerifier interface {
    VerifyToken(r *http.Request, jwkAuth *JwkAuthOptions) (map[string]interface{}, error)
}

type GenericTokenVerifier struct {
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
        Verifier:  &GenericTokenVerifier{},
        RenewKeys: false,
    }, nil
}

// AuthMiddleware is the middleware for authenticating requests.
func AuthMiddleware(a *JwkAuthOptions) func(next http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        fn := func(w http.ResponseWriter, r *http.Request) {

            // verify token
            token, err := a.Verifier.VerifyToken(r, a)
            if err != nil {
                w.WriteHeader(http.StatusUnauthorized)
                return
            }

            // add token to context
            ctx := context.WithValue(r.Context(), JwtTokenKey, token)

            next.ServeHTTP(w, r.WithContext(ctx))
        }
        return http.HandlerFunc(fn)
    }
}

// VerifyToken verifies the token from the request and returns the claims.
func (g *GenericTokenVerifier) VerifyToken(r *http.Request, jwkAuth *JwkAuthOptions) (map[string]interface{}, error) {
    // get token from header
    stringToken, err := getTokenFromHeader(r)
    if err != nil {
        return nil, err
    }

    // parse token
    token, err := jwt.Parse([]byte(stringToken), jwt.WithKeySet(jwkAuth.JwkSet), jwt.WithValidate(true))
    if err != nil {
        return nil, errors.New("could not parse token")
    }

    // check issuer
    if token.Issuer() != jwkAuth.Issuer {
        return nil, errors.New("issuer does not match")
    }

    // get claims
    claims, err := token.AsMap(r.Context())
    if err != nil {
        return nil, errors.New("could not decode token")
    }

    return claims, nil
}

func getTokenFromHeader(r *http.Request) (string, error) {
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        return "", errors.New("no authorization header provided")
    }
    tokenParts := strings.Fields(authHeader)
    if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
        return "", errors.New("invalid authorization header")
    }
    return tokenParts[1], nil
}

// DecodeToken decodes the token from the context into the token struct.
func DecodeToken(ctx context.Context, token any) error {
    claims, ok := ctx.Value(JwtTokenKey).(map[string]interface{})
    if !ok {
        return errors.New("could not get token from context")
    }

    err := mapstructure.Decode(claims, token)
    if err != nil {
        return errors.New("failed to decode token")
    }
    return nil
}
