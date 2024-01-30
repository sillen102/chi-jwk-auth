package main

import (
    "log"
    "net/http"
    "strings"

    "github.com/go-chi/chi/v5"

    "github.com/sillen102/chi-jwk-auth/chiJwk"
    "github.com/sillen102/chi-jwk-auth/keycloak"
)

// MyToken is the struct for the token claims, needs to implement chiJwk.Token interface
type MyToken struct {
    UserID        string      `mapstructure:"sub"`
    FirstName     string      `mapstructure:"given_name"`
    LastName      string      `mapstructure:"family_name"`
    Email         string      `mapstructure:"email"`
    EmailVerified bool        `mapstructure:"email_verified"`
    RealmAccess   RealmAccess `mapstructure:"realm_access"`
    Scope         string      `mapstructure:"scope"`
}

type RealmAccess struct {
    Roles []string `mapstructure:"tokenRoles"`
}

// Roles returns the roles of the token. Must not use pointer receiver.
func (t MyToken) Roles() []string {
    return t.RealmAccess.Roles
}

// Scopes returns the scopes of the token. Must not use pointer receiver.
func (t MyToken) Scopes() []string {
    return strings.Split(t.Scope, " ")
}

func main() {
    // create jwk auth middleware with jwks key set
    authOptions, err := chiJwk.NewJwkOptions(
        "http://localhost:8080/realms/MyRealm",
        "http://localhost:8080/realms/MyRealm/protocol/openid-connect/certs",
    )
    if err != nil {
        log.Fatal("could not create jwk auth middleware")
    }

    // create router
    r := chi.NewRouter()
    setupRouter(r, authOptions)

    // start server
    log.Println("started server on localhost:8000")
    log.Fatal(http.ListenAndServe("localhost:8000", r))
}

// setupRouter sets up the router with jwk auth middleware.
func setupRouter(r *chi.Mux, jwkAuth *chiJwk.JwkAuthOptions) {
    r.Use(jwkAuth.AuthMiddleware())

    // With function level filter options
    r.Get("/api/admin", keycloak.WithFilter(keycloak.FilterOptions{
        FilterRoles:  []string{"admin"},
        FilterScopes: []string{"profile"},
    }, myHandler))

    // With middleware filter options
    r.Group(func(r chi.Router) {
        r.Use(jwkAuth.AuthMiddleware(&keycloak.FilterOptions{
            FilterRoles:  []string{"admin"},
            FilterScopes: []string{"profile"},
        }))
        r.Get("/api/middleware-filter", myHandler)
    })

    // Without middleware level filter options
    r.Group(func(r chi.Router) {
        r.Use(jwkAuth.AuthMiddleware())
        r.Get("/api/secure", myHandler)
    })
}

// myHandler is the handler for the secure endpoint.
func myHandler(w http.ResponseWriter, r *http.Request) {
    // get token from context
    var token MyToken
    err := chiJwk.GetClaims(r.Context(), &token)
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }

    // write response
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte("Hello " + token.FirstName + " " + token.LastName))
}
