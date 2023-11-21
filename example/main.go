package main

import (
    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    "github.com/sillen102/chi-jwk-auth/keycloak"
    "net/http"
)

func main() {
    r := chi.NewRouter()
    r.Use(middleware.Logger)
    r.Use(keycloak.AuthMiddleware)
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("welcome"))
    })
    http.ListenAndServe("localhost:3000", r)
}
