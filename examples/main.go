package main

import (
    "log"
    "net/http"

    "github.com/go-chi/chi/v5"

    "github.com/sillen102/chi-jwk-auth/chiJwk"
    "github.com/sillen102/chi-jwk-auth/keycloak"
)

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
    Roles []string `mapstructure:"roles"`
}

func main() {
    // create jwk auth middleware with jwks key set
    authOptions, err := chiJwk.NewJwkOptions("http://localhost:8080/realms/MyRealm")
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

    // Without filter options
    r.Get("/api/secure", myHandler)

    // With filter options
    r.Get("/api/admin", keycloak.WithFilter(keycloak.FilterOptions{
        Roles:  []string{"admin"},
        Scopes: []string{"profile"},
    }, myHandler))
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
