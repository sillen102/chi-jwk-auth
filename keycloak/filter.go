package keycloak

import (
    "net/http"

    "github.com/mitchellh/mapstructure"

    "github.com/sillen102/chi-jwk-auth/chiJwk"
)

type FilterOptions struct {
    Roles  []string
    Scopes []string
}

func WithFilter(opts FilterOptions, handlerFunc func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
    return func(w http.ResponseWriter, r *http.Request) {
        claims, ok := r.Context().Value(chiJwk.JwtTokenKey).(map[string]interface{})
        if !ok {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }

        // Convert claims to JwtToken struct
        var token JwtToken
        err := mapstructure.Decode(claims, &token)
        if err != nil {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }

        if !chiJwk.TokenHasRequiredRoles(token.Roles(), opts.Roles) {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }

        if !chiJwk.TokenHasRequiredScopes(token.Scopes(), opts.Scopes) {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }

        handlerFunc(w, r)
    }
}
