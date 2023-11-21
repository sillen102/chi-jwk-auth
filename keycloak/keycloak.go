package keycloak

import (
	"context"
	"errors"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/mitchellh/mapstructure"
	"net/http"
	"strings"
)

// JwkAuth is the struct for the jwk auth
type JwkAuth struct {
	JwkSet jwk.Set
}

// Token is the struct for the token claims
type Token struct {
	UserID        string   `mapstructure:"sub"`
	FirstName     string   `mapstructure:"given_name"`
	LastName      string   `mapstructure:"family_name"`
	Email         string   `mapstructure:"email"`
	EmailVerified bool     `mapstructure:"email_verified"`
	Roles         []string `mapstructure:"roles"`
}

// AuthMiddleware is the middleware for authenticating requests
func (s *JwkAuth) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// verify token
		token, err := verifyToken(r, s.JwkSet)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// add token to context
		ctx := context.WithValue(r.Context(), Token{}, token)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func verifyToken(r *http.Request, jwksKeySet jwk.Set) (*Token, error) {
	// get token from header
	stringToken, err := getTokenFromHeader(r)
	if err != nil {
		return nil, err
	}

	// parse token
	token, err := jwt.Parse([]byte(stringToken), jwt.WithKeySet(jwksKeySet), jwt.WithValidate(true))
	if err != nil {
		return nil, errors.New("could not parse token")
	}

	// decode token
	var claims Token
	err = mapstructure.Decode(token, claims)
	if err != nil {
		return nil, errors.New("could not decode token")
	}

	return &claims, nil
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
