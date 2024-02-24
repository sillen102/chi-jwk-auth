package chiJwk

import (
    "context"
    "errors"
    "fmt"
    "net/http"

    "github.com/golang-jwt/jwt/request"
    "github.com/lestrrat-go/jwx/v2/jwk"
    "github.com/lestrrat-go/jwx/v2/jwt"
    "github.com/mitchellh/mapstructure"
)

// JwtTokenKey is the key for the jwt token in the context.
const JwtTokenKey = "jwt-token"

// JwkAuthOptions is the struct for the jwk auth middleware.
type JwkAuthOptions struct {
    AuthenticationType AuthenticationType
    CookieOptions      CookieOptions
    JwkSet             jwk.Set
    Issuer             string
    IssuerJwkUrl       string
    Filter             Filter
    CreateToken        func(claims map[string]interface{}) (Token, error)
}

type AuthenticationType int

type CookieOptions struct {
    Name string
}

const (
    Cookie AuthenticationType = iota
    Bearer
)

type Token interface {
    Roles() []string
    Scopes() []string
}

type Filter interface {
    Roles() []string
    Scopes() []string
}

type DefaultFilter struct {
    FilterRoles  []string
    FilterScopes []string
}

func (f DefaultFilter) Roles() []string {
    return f.FilterRoles
}

func (f DefaultFilter) Scopes() []string {
    return f.FilterScopes
}

// NewJwkOptions creates a new jwk auth middleware.
func NewJwkOptions(issuer string, jwksUrl string) (*JwkAuthOptions, error) {
    jwksSet, err := jwk.Fetch(context.Background(), jwksUrl)
    if err != nil {
        return nil, errors.New("could not fetch jwks key set")
    }

    return &JwkAuthOptions{
        AuthenticationType: Cookie,
        CookieOptions:      CookieOptions{Name: "access-token"},
        JwkSet:             jwksSet,
        Issuer:             issuer,
        IssuerJwkUrl:       jwksUrl,
        Filter:             DefaultFilter{FilterRoles: make([]string, 0), FilterScopes: make([]string, 0)},
        CreateToken:        CreateTokenFromClaims[Token],
    }, nil
}

// WithAuthenticationType sets the authentication type option that determines how the token
// is extracted from the request.
func (options *JwkAuthOptions) WithAuthenticationType(authenticationType AuthenticationType) *JwkAuthOptions {
    options.AuthenticationType = authenticationType
    return options
}

// WithCookieOptions sets the cookie options that determines how the cookie is extracted from the request.
func (options *JwkAuthOptions) WithCookieOptions(cookieOptions CookieOptions) *JwkAuthOptions {
    options.CookieOptions = cookieOptions
    return options
}

// WithIssuer sets the issuer option that determines the issuer of the tokens.
func (options *JwkAuthOptions) WithIssuer(issuer string) *JwkAuthOptions {
    options.Issuer = issuer
    return options
}

// WithIssuerJwkUrl sets the issuer JWK URL option that determines where the JWK Set should
// be fetched from.
func (options *JwkAuthOptions) WithIssuerJwkUrl(issuerJwkUrl string) *JwkAuthOptions {
    options.IssuerJwkUrl = issuerJwkUrl
    return options
}

// WithFilter sets the filter option that determines the roles and scopes that are required
// for the token.
func (options *JwkAuthOptions) WithFilter(filter Filter) *JwkAuthOptions {
    options.Filter = filter
    return options
}

// WithCreateToken sets the create token option that determines how the token is created.
func (options *JwkAuthOptions) WithCreateToken(createToken func(claims map[string]interface{}) (Token, error)) *JwkAuthOptions {
    options.CreateToken = createToken
    return options
}

// AuthMiddleware is the middleware for authenticating requests.
func (options *JwkAuthOptions) AuthMiddleware(filter ...Filter) func(next http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {

        fn := func(w http.ResponseWriter, r *http.Request) {
            ctx := r.Context()
            log := FromCtx(ctx)

            // Get the token from the request
            var tokenStr string
            switch options.AuthenticationType {
            case Bearer:
                token, err := request.AuthorizationHeaderExtractor.ExtractToken(r)
                if err != nil {
                    log.Debug(fmt.Sprintf("invalid authorization header %v", err))
                    w.WriteHeader(http.StatusUnauthorized)
                    return
                }
                tokenStr = token
            case Cookie:
                // Get the access token from the cookie
                accessCookie, err := r.Cookie(options.CookieOptions.Name)
                if err != nil {
                    log.Debug(fmt.Sprintf("access token cookie required %v", err))
                    w.WriteHeader(http.StatusUnauthorized)
                    return
                }
                tokenStr = accessCookie.Value
            }

            // Parse and verify the token
            jwtToken, err := jwt.Parse([]byte(tokenStr), jwt.WithKeySet(options.JwkSet), jwt.WithValidate(true))
            if err != nil {
                log.Debug(fmt.Sprintf("invalid token %v", err))
                w.WriteHeader(http.StatusUnauthorized)
                return
            }

            // Check the issuer
            if jwtToken.Issuer() != options.Issuer {
                log.Debug("invalid issuer")
                w.WriteHeader(http.StatusUnauthorized)
                return
            }

            // Get claims
            claims, err := jwtToken.AsMap(r.Context())
            if err != nil {
                log.Debug(fmt.Sprintf("invalid token claims %v", err))
                w.WriteHeader(http.StatusUnauthorized)
                return
            }

            // Create token instance
            token, err := options.CreateToken(claims)
            if err != nil {
                log.Debug(fmt.Sprintf("invalid token claims %v", err))
                w.WriteHeader(http.StatusUnauthorized)
                return
            }

            // Check if the token passes filters
            for _, f := range filter {
                if f == nil {
                    continue
                }

                if !TokenHasRequiredRoles(token.Roles(), f.Roles()) {
                    log.Debug("invalid token roles")
                    w.WriteHeader(http.StatusUnauthorized)
                    return
                }

                if !TokenHasRequiredScopes(token.Scopes(), f.Scopes()) {
                    log.Debug("invalid token scopes")
                    w.WriteHeader(http.StatusUnauthorized)
                    return
                }
            }

            // Add claims to context
            ctx = context.WithValue(r.Context(), JwtTokenKey, claims)

            // Call the next handler
            next.ServeHTTP(w, r.WithContext(ctx))
        }

        return http.HandlerFunc(fn)
    }
}

// GetClaims extracts the token claims from the context into the provided object.
func GetClaims(ctx context.Context, token Token) error {
    claims, ok := ctx.Value(JwtTokenKey).(map[string]interface{})
    if !ok {
        return errors.New("could not get token from context")
    }

    err := mapstructure.Decode(claims, token)
    if err != nil {
        return fmt.Errorf("failed to decode token: %w", err)
    }

    return nil
}

// CreateTokenFromClaims create a token from claims.
// The token must implement the Token interface and have mapstructure tags.
func CreateTokenFromClaims[T Token](claims map[string]interface{}) (Token, error) {
    var token T
    err := mapstructure.Decode(claims, &token)
    if err != nil {
        return nil, err
    }
    return token, nil
}

// TokenHasRequiredRoles checks if the token has the required scopes.
func TokenHasRequiredRoles(tokenRoles []string, requiredRoles []string) bool {
    if requiredRoles == nil || len(requiredRoles) == 0 {
        return true
    }

    // Create a map for quick lookup of token roles
    tokenRolesMap := make(map[string]bool)
    for _, role := range tokenRoles {
        tokenRolesMap[role] = true
    }

    // Check if all required roles are in the token roles
    for _, requiredRole := range requiredRoles {
        if _, ok := tokenRolesMap[requiredRole]; !ok {
            return false
        }
    }

    return true
}

// TokenHasRequiredScopes checks if the token has the required scopes.
func TokenHasRequiredScopes(tokenScopes []string, requiredScopes []string) bool {
    // Create a map for quick lookup of token scopes
    tokenScopesMap := make(map[string]bool)
    for _, scope := range tokenScopes {
        tokenScopesMap[scope] = true
    }

    // Check if all required scopes are in the token scopes
    for _, requiredScope := range requiredScopes {
        if _, ok := tokenScopesMap[requiredScope]; !ok {
            return false
        }
    }

    return true
}
