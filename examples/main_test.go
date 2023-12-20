package main

import (
    "io"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/go-chi/chi/v5"
    "github.com/stretchr/testify/require"

    "github.com/sillen102/chi-jwk-auth/middleware"
)

type MockVerifier struct {
}

func (v *MockVerifier) VerifyToken(_ *http.Request, _ *middleware.JwkAuthOptions) (map[string]interface{}, error) {
    return map[string]interface{}{
        "sub":         "123",
        "given_name":  "John",
        "family_name": "Doe",
    }, nil
}

func TestExample(t *testing.T) {
    // create jwk auth middleware with jwks key set
    jwkAuth := &middleware.JwkAuthOptions{
        JwkSet:   nil,
        Issuer:   "",
        Verifier: &MockVerifier{},
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
