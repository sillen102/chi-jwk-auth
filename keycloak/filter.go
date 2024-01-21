package keycloak

import (
    "net/http"
    "strings"

    "github.com/sillen102/chi-jwk-auth/chiJwk"
)

type FilterOptions struct {
    Roles  []string
    Scopes []string
}

func WithFilter(opts FilterOptions, handlerFunc func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
    return func(w http.ResponseWriter, r *http.Request) {
        claims, ok := r.Context().Value(chiJwk.JwtTokenKey).(map[string]interface{})
        if !ok {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }

        userRoles, ok := getUserRolesFromClaims(claims)
        if !ok {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }

        if !userHasRequiredRoles(userRoles, opts.Roles) {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }

        scopes, ok := getScopesFromClaims(claims)
        if !ok {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }

        if !tokenHasRequiredScopes(scopes, opts.Scopes) {
            w.WriteHeader(http.StatusUnauthorized)
            return
        }

        handlerFunc(w, r)
    }
}

func getUserRolesFromClaims(claims map[string]interface{}) (map[string]bool, bool) {
    userRolesInterface, ok := claims["realm_access"].(map[string]interface{})["tokenRoles"].([]interface{})
    if !ok {
        return nil, false
    }

    userRoles := make(map[string]bool)
    for _, role := range userRolesInterface {
        userRoles[role.(string)] = true
    }

    return userRoles, true
}

func userHasRequiredRoles(userRoles map[string]bool, requiredRoles []string) bool {
    if requiredRoles == nil || len(requiredRoles) == 0 {
        return true
    }

    for _, role := range requiredRoles {
        if _, ok := userRoles[role]; ok {
            return true
        }
    }
    return false
}

func getScopesFromClaims(claims map[string]interface{}) (map[string]bool, bool) {
    scopes, ok := claims["scope"].(string)
    if !ok {
        return nil, false
    }

    scopesSlice := strings.Split(scopes, " ")
    scopesMap := make(map[string]bool)
    for _, scope := range scopesSlice {
        scopesMap[scope] = true
    }

    return scopesMap, true
}

func tokenHasRequiredScopes(scopesMap map[string]bool, requiredScopes []string) bool {
    if requiredScopes == nil || len(requiredScopes) == 0 {
        return true
    }

    for _, scope := range requiredScopes {
        if _, ok := scopesMap[scope]; ok {
            return true
        }
    }
    return false
}
