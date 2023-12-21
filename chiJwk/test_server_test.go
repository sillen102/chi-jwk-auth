package chiJwk_test

import (
    "context"
    "net/http"
    "testing"

    "github.com/stretchr/testify/assert"

    "github.com/sillen102/chi-jwk-auth/chiJwk"
)

func TestTestServer(t *testing.T) {
    // Define the test cases
    testCases := []struct {
        name           string
        claims         map[string]interface{}
        expectedStatus int
    }{
        {
            name: "Test issuing a token with valid claims",
            claims: map[string]interface{}{
                "sub": "1234567890",
            },
            expectedStatus: http.StatusOK,
        },
        {
            name:           "Test issuing a token with empty claims",
            claims:         map[string]interface{}{},
            expectedStatus: http.StatusOK,
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            // Create a new TestServer
            testServer, err := chiJwk.NewTestServer("")
            if err != nil {
                t.Fatalf("Error creating test server: %v", err)
            }
            defer testServer.Stop(context.Background())

            // Test that the server starts successfully and returns the correct issuer URL
            assert.NotEmpty(t, testServer.Issuer)

            // Test that the server issues a token successfully
            token, err := testServer.IssueToken(tc.claims)
            assert.NoError(t, err)
            assert.NotEmpty(t, token)

            // Test that the server serves the JWK Set correctly
            resp, err := http.Get(testServer.Issuer + "/keys")
            if err != nil {
                t.Fatalf("Error making GET request: %v", err)
            }
            defer resp.Body.Close()
            assert.Equal(t, tc.expectedStatus, resp.StatusCode)
        })
    }

    // Test fetching the JWK Set when the server is not running
    t.Run("Test fetching JWK Set when server is not running", func(t *testing.T) {
        resp, err := http.Get("http://localhost:9999/keys") // Use a port where no server is running
        if err == nil {
            err = resp.Body.Close()
            if err != nil {
                t.Fatal(err)
            }
        }
        assert.Error(t, err)
    })
}
