package main

import (
    "context"
    "github.com/go-chi/chi/v5"
    "github.com/lestrrat-go/jwx/v2/jwk"
    "github.com/sillen102/chi-jwk-auth/middleware"
    "log"
    "net/http"
)

func main() {
    // get jwks key set
    jwksKeySet, err := jwk.Fetch(context.Background(), "http://localhost:8080/realms/MyRealm/protocol/openid-connect/certs")
    if err != nil {
        log.Fatal("could not fetch jwks key set")
    }

    // create jwk auth middleware with jwks key set
    jwkAuth := middleware.JwkAuth{
        JwkSet: jwksKeySet,
    }

    r := chi.NewRouter()
    r.Use(jwkAuth.AuthMiddleware)

    r.Get("/secure", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("welcome"))
    })

    http.ListenAndServe("localhost:3000", r)
}
