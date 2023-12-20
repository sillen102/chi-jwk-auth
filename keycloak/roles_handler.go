package keycloak

import (
    "net/http"

    "github.com/sillen102/chi-jwk-auth/middleware"
)

// WithAllowedRoles is a wrapper for a handler function that checks if the user has the required roles.
func WithAllowedRoles(roles []string, handlerFunc func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
    return func(w http.ResponseWriter, r *http.Request) {
        claims, ok := r.Context().Value(middleware.JwtTokenKey).(map[string]interface{})
        if !ok {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }

        // get user roles from claims
        userRolesInterface, ok := claims["realm_access"].(map[string]interface{})["roles"].([]string)
        if !ok {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }

        // convert user roles to map for constant time lookup
        userRoles := make(map[string]bool)
        for _, role := range userRolesInterface {
            userRoles[role] = true
        }

        // check if user has required roles
        for _, role := range roles {
            if _, ok = userRoles[role]; ok {
                handlerFunc(w, r)
                return
            }
        }

        w.WriteHeader(http.StatusUnauthorized)
    }
}
