package keycloak_test

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/stretchr/testify/assert"

    "github.com/sillen102/chi-jwk-auth/chiJwk"
    "github.com/sillen102/chi-jwk-auth/keycloak"
)

func TestWithFilter(t *testing.T) {
    // Define the test cases
    tests := []struct {
        name           string
        roles          []interface{}
        scopes         string
        expectedStatus int
    }{
        {
            name:           "Authorized - correct roles and scopes",
            roles:          []interface{}{"role1", "role2"},
            scopes:         "scope1 scope2",
            expectedStatus: http.StatusOK,
        },
        {
            name:           "Unauthorized - no roles or scopes",
            roles:          []interface{}{},
            scopes:         "",
            expectedStatus: http.StatusUnauthorized,
        },
        {
            name:           "Unauthorized - scopes match, roles do not",
            roles:          []interface{}{"role3"},
            scopes:         "scope1 scope2",
            expectedStatus: http.StatusUnauthorized,
        },
        {
            name:           "Unauthorized - neither roles nor scopes match",
            roles:          []interface{}{"role3"},
            scopes:         "scope3",
            expectedStatus: http.StatusUnauthorized,
        },
    }

    // Run the tests
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Create a mock HTTP request and response writer
            req, err := http.NewRequest("GET", "/", nil)
            if err != nil {
                t.Fatal(err)
            }

            // Mock the request context to include the roles and scopes
            ctx := context.WithValue(req.Context(), chiJwk.JwtTokenKey, map[string]interface{}{
                "realm_access": map[string]interface{}{
                    "roles": tt.roles,
                },
                "scope": tt.scopes,
            })
            req = req.WithContext(ctx)

            rr := httptest.NewRecorder()

            // Create a handler function for testing
            handlerFunc := func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusOK)
            }

            // Create a FilterOptions instance for testing
            opts := keycloak.FilterOptions{
                Roles:  []string{"role1", "role2"},
                Scopes: []string{"scope1", "scope2"},
            }

            // Call WithFilter with the mock request and handler function
            keycloak.WithFilter(opts, handlerFunc)(rr, req)

            // Check the status code of the response
            assert.Equal(t, tt.expectedStatus, rr.Code)
        })
    }
}
