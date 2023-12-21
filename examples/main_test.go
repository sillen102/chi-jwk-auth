package main

import (
    "bytes"
    "context"
    "encoding/json"
    "io"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/go-chi/chi/v5"
    "github.com/stretchr/testify/require"

    "github.com/sillen102/chi-jwk-auth/chiJwk"
)

func TestExample(t *testing.T) {
    // create a new jwk TestServer
    testServer, err := chiJwk.NewTestServer("")
    if err != nil {
        t.Fatalf("Error creating test server: %v", err)
    }
    defer testServer.Stop(context.Background())

    // create jwk auth middleware with jwks key set
    jwkAuth := &chiJwk.JwkAuthOptions{
        JwkSet:       testServer.JwkSet,
        Issuer:       testServer.Issuer,
        IssuerJwkUrl: "/keys",
        RenewKeys:    false,
    }

    // get token from test server
    userToken := map[string]interface{}{
        "sub":            "1234567890",
        "given_name":     "John",
        "family_name":    "Doe",
        "email":          "john.doe@example.com",
        "email_verified": true,
        "realm_access":   map[string][]string{"roles": {"user"}},
    }
    userTokenJson, err := json.Marshal(userToken)
    if err != nil {
        t.Fatalf("Error converting user token to JSON: %v", err)
    }
    tokenResponse, err := http.Post(testServer.Issuer+"/issue", "application/json", bytes.NewBuffer(userTokenJson))
    if err != nil {
        t.Fatalf("Error getting token: %v", err)
    }
    tokenBytes, err := io.ReadAll(tokenResponse.Body)
    if err != nil {
        t.Fatalf("Error reading token response: %v", err)
    }

    // create test server
    r := chi.NewRouter()
    setupRouter(r, jwkAuth)
    ts := httptest.NewServer(r)
    defer ts.Close()

    // make request
    req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/secure", nil)
    req.Header.Set("Authorization", "Bearer "+string(tokenBytes))
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
