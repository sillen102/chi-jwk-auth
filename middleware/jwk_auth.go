package middleware

import (
    "context"
    "errors"
    "net/http"
    "strings"

    "github.com/lestrrat-go/jwx/v2/jwk"
    "github.com/lestrrat-go/jwx/v2/jwt"
    "github.com/mitchellh/mapstructure"
)

const JwtTokenKey = "jwt-token"

// JwkAuth is the struct for the jwk auth middleware.
type JwkAuth struct {
    JwkSet   jwk.Set
    Issuer   string
    Verifier TokenVerifier
}

// TokenVerifier is the interface for a verifier,
// you can use the GenericTokenVerifier or create your own implementation (useful in testing).
type TokenVerifier interface {
    VerifyToken(r *http.Request, jwkAuth JwkAuth) (map[string]interface{}, error)
}

type GenericTokenVerifier struct {
}

// NewJwkAuth creates a new jwk auth middleware.
func NewJwkAuth(issuer string) (*JwkAuth, error) {
    jwksSet, err := jwk.Fetch(context.Background(), issuer+"/protocol/openid-connect/certs")
    if err != nil {
        return nil, errors.New("could not fetch jwks key set")
    }

    return &JwkAuth{
        JwkSet:   jwksSet,
        Issuer:   issuer,
        Verifier: &GenericTokenVerifier{},
    }, nil
}

// AuthMiddleware is the middleware for authenticating requests.
func AuthMiddleware(a JwkAuth) func(next http.Handler) http.Handler {
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
func (g *GenericTokenVerifier) VerifyToken(r *http.Request, jwkAuth JwkAuth) (map[string]interface{}, error) {
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

    claims, err := token.AsMap(r.Context())
    if err != nil {
        return nil, errors.New("could not decode token")
    }

    return claims, nil
}

func getTokenFromHeader(r *http.Request) (string, error) {
    authHeader := strings.Split(r.Header.Get("Authorization"), " ")
    if authHeader[0] != "Bearer" || len(authHeader) != 2 {
        return "", errors.New("no bearer token provided")
    }
    if authHeader[1] == "" {
        return "", errors.New("no authorization token provided")
    }
    stringToken := authHeader[1]
    return stringToken, nil
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
