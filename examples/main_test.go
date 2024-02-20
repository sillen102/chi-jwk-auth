package main

import (
    "context"
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
        Filter:       chiJwk.DefaultFilter{FilterRoles: make([]string, 0), FilterScopes: make([]string, 0)},
        CreateToken:  chiJwk.CreateTokenFromClaims[MyToken],
    }

    // create a new router
    r := chi.NewRouter()
    setupRouter(r, jwkAuth)

    // Define the test cases
    testCases := []struct {
        name           string
        endpoint       string
        token          string
        expectedStatus int
    }{
        {
            name:           "Test /api/secure endpoint",
            endpoint:       "/api/secure",
            token:          userToken(t, testServer),
            expectedStatus: http.StatusOK,
        },
        {
            name:           "Test /api/admin endpoint",
            endpoint:       "/api/admin",
            token:          adminToken(t, testServer),
            expectedStatus: http.StatusOK,
        },
        {
            name:           "Test /api/middleware-filter endpoint",
            endpoint:       "/api/middleware-filter",
            token:          adminToken(t, testServer),
            expectedStatus: http.StatusOK,
        },
        {
            name:           "Test /api/secure endpoint with no token",
            endpoint:       "/api/secure",
            token:          "",
            expectedStatus: http.StatusUnauthorized,
        },
        {
            name:           "Test /api/secure endpoint with invalid token",
            endpoint:       "/api/secure",
            token:          "invalid",
            expectedStatus: http.StatusUnauthorized,
        },
        {
            name:           "Test /api/admin endpoint with no token",
            endpoint:       "/api/admin",
            token:          "",
            expectedStatus: http.StatusUnauthorized,
        },
        {
            name:           "Test /api/admin endpoint with invalid token",
            endpoint:       "/api/admin",
            token:          "invalid",
            expectedStatus: http.StatusUnauthorized,
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            // create a new request
            req, err := http.NewRequest("GET", tc.endpoint, nil)
            if err != nil {
                t.Fatalf("Error creating request: %v", err)
            }

            // set the Authorization header
            req.Header.Set("Authorization", "Bearer "+tc.token)

            // create a new recorder
            rec := httptest.NewRecorder()

            // serve the request
            r.ServeHTTP(rec, req)

            // assert the status code
            require.Equal(t, tc.expectedStatus, rec.Code)
        })
    }
}

func userToken(t *testing.T, testServer *chiJwk.TestServer) string {
    myUserToken, err := testServer.IssueToken(MyToken{
        UserID:        "1234567890",
        FirstName:     "John",
        LastName:      "Doe",
        Email:         "john.doe@example.com",
        EmailVerified: true,
        RealmAccess: RealmAccess{
            Roles: []string{"user"},
        },
        Scope: "profile",
    })

    if err != nil {
        t.Fatalf("Error issuing token: %v", err)
    }

    return myUserToken
}

func adminToken(t *testing.T, testServer *chiJwk.TestServer) string {
    myAdminToken, err := testServer.IssueToken(MyToken{
        UserID:        "1234567890",
        FirstName:     "John",
        LastName:      "Doe",
        Email:         "john.doe@example.com",
        EmailVerified: true,
        RealmAccess: RealmAccess{
            Roles: []string{"admin"},
        },
        Scope: "profile",
    })

    if err != nil {
        t.Fatalf("Error issuing token: %v", err)
    }

    return myAdminToken
}
