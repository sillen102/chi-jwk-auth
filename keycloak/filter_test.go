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
        tokenRoles     []interface{}
        requiredRoles  []string
        tokenScopes    string
        requiredScopes []string
        expectedStatus int
    }{
        {
            name:           "Authorized - correct token roles and token scopes",
            tokenRoles:     []interface{}{"role1", "role2"},
            requiredRoles:  []string{"role1", "role2"},
            tokenScopes:    "scope1 scope2",
            requiredScopes: []string{"scope1", "scope2"},
            expectedStatus: http.StatusOK,
        },
        {
            name:           "Authorized - no required roles",
            tokenRoles:     []interface{}{"role1", "role2"},
            requiredRoles:  nil,
            tokenScopes:    "scope1 scope2",
            requiredScopes: []string{"scope1", "scope2"},
            expectedStatus: http.StatusOK,
        },
        {
            name:           "Authorized - no required scopes",
            tokenRoles:     []interface{}{"role1", "role2"},
            requiredRoles:  []string{"role1", "role2"},
            tokenScopes:    "scope1 scope2",
            requiredScopes: nil,
            expectedStatus: http.StatusOK,
        },
        {
            name:           "Unauthorized - no token roles or token scopes",
            tokenRoles:     []interface{}{},
            requiredRoles:  []string{"role1", "role2"},
            tokenScopes:    "",
            requiredScopes: []string{"scope1", "scope2"},
            expectedStatus: http.StatusUnauthorized,
        },
        {
            name:           "Unauthorized - token scopes match, token roles do not",
            tokenRoles:     []interface{}{"role3"},
            requiredRoles:  []string{"role1", "role2"},
            tokenScopes:    "scope1 scope2",
            requiredScopes: []string{"scope1", "scope2"},
            expectedStatus: http.StatusUnauthorized,
        },
        {
            name:           "Unauthorized - neither token roles nor token scopes match",
            tokenRoles:     []interface{}{"role3"},
            requiredRoles:  []string{"role1", "role2"},
            tokenScopes:    "scope3",
            requiredScopes: []string{"scope1", "scope2"},
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

            // Mock the request context to include the tokenRoles and tokenScopes
            ctx := context.WithValue(req.Context(), chiJwk.JwtTokenKey, map[string]interface{}{
                "realm_access": map[string]interface{}{
                    "roles": tt.tokenRoles,
                },
                "scope": tt.tokenScopes,
            })
            req = req.WithContext(ctx)

            rr := httptest.NewRecorder()

            // Create a handler function for testing
            handlerFunc := func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusOK)
            }

            // Create a FilterOptions instance for testing
            opts := keycloak.FilterOptions{
                FilterRoles:  tt.requiredRoles,
                FilterScopes: tt.requiredScopes,
            }

            // Call WithFilter with the mock request and handler function
            keycloak.WithFilter(opts, handlerFunc)(rr, req)

            // Check the status code of the response
            assert.Equal(t, tt.expectedStatus, rr.Code)
        })
    }
}
