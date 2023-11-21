package main

import (
    "github.com/go-chi/chi/v5"
    "github.com/sillen102/chi-jwk-auth/middleware"
    "github.com/stretchr/testify/require"
    "io"
    "net/http"
    "net/http/httptest"
    "testing"
)

type MyVerifier struct {
}

func (v *MyVerifier) VerifyToken(_ *http.Request, _ *middleware.JwkAuth) (map[string]interface{}, error) {
    return map[string]interface{}{
        "sub":         "123",
        "given_name":  "John",
        "family_name": "Doe",
    }, nil
}

func TestExample(t *testing.T) {
    // create jwk auth middleware with jwks key set
    jwkAuth := &middleware.JwkAuth{
        JwkSet:   nil,
        Issuer:   "",
        Verifier: &MyVerifier{},
    }

    // create test server
    r := chi.NewRouter()
    setupRouter(r, jwkAuth)
    ts := httptest.NewServer(r)
    defer ts.Close()

    // make request
    req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/secure", nil)
    require.NoError(t, err)

    resp, err := http.DefaultClient.Do(req)
    require.NoError(t, err)

    // read response
    respBody, err := io.ReadAll(resp.Body)
    require.NoError(t, err)

    // assert response
    require.Equal(t, http.StatusOK, resp.StatusCode)
    require.Equal(t, "Hello John Doe", string(respBody))
}
