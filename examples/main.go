package main

import (
    "log"
    "net/http"

    "github.com/go-chi/chi/v5"
    "github.com/sillen102/chi-jwk-auth/middleware"
)

type MyToken struct {
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

func main() {
    // create jwk auth middleware with jwks key set
    jwkAuth, err := middleware.NewJwkAuth("http://localhost:8080/realms/MyRealm")
    if err != nil {
        log.Fatal("could not create jwk auth middleware")
    }

    r := chi.NewRouter()
    setupRouter(r, jwkAuth)

    http.ListenAndServe("localhost:3000", r)
}

func setupRouter(r *chi.Mux, jwkAuth *middleware.JwkAuth) {
    r.Use(middleware.AuthMiddleware(jwkAuth))
    r.Get("/api/secure", myHandler)
}

func myHandler(w http.ResponseWriter, r *http.Request) {
    var token MyToken
    err := middleware.DecodeToken(r.Context(), &token)
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Hello " + token.FirstName + " " + token.LastName))
}
