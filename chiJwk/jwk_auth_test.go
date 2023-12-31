package chiJwk_test

import (
    "crypto/rand"
    "crypto/rsa"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "github.com/lestrrat-go/jwx/v2/jwa"
    "github.com/lestrrat-go/jwx/v2/jwk"
    "github.com/lestrrat-go/jwx/v2/jws"
    "github.com/lestrrat-go/jwx/v2/jwt"
    "github.com/stretchr/testify/assert"

    "github.com/sillen102/chi-jwk-auth/chiJwk"
)

const kidValue = "my-key-id"
const issuerValue = "my-issuer"
const audienceValue = "my-audience"
const subjectValue = "my-subject"
const tokenIdValue = "my-token-id"

func TestAuthMiddleware(t *testing.T) {
    // Create a new JWK Set and JWK key
    jwkSet, privateKey := createJwkKeysAndSet(t)

    // Create a mock JwkAuthOptions
    jwkAuthOptions := &chiJwk.JwkAuthOptions{
        JwkSet: jwkSet,
        Issuer: issuerValue,
    }

    tests := []struct {
        name           string
        token          string
        expectedStatus int
    }{
        {
            name:           "With Valid Token",
            token:          createValidToken(t, privateKey),
            expectedStatus: http.StatusOK,
        },
        {
            name:           "With Invalid Token",
            token:          "invalid-token",
            expectedStatus: http.StatusUnauthorized,
        },
        {
            name:           "With Expired Token",
            token:          createTokenWithExpiration(t, privateKey, time.Now().Add(-time.Minute)),
            expectedStatus: http.StatusUnauthorized,
        },
        {
            name:           "With Not Yet Valid Token",
            token:          createTokenWithNotBefore(t, privateKey, time.Now().Add(time.Minute)),
            expectedStatus: http.StatusUnauthorized,
        },
        {
            name:           "With Invalid Signature Token",
            token:          createValidToken(t, privateKey) + "invalid",
            expectedStatus: http.StatusUnauthorized,
        },
        {
            name:           "With Invalid Kid Token",
            token:          createTokenWithKid(t, privateKey, "invalid-kid"),
            expectedStatus: http.StatusUnauthorized,
        },
        {
            name:           "With Invalid Issuer Token",
            token:          createTokenWithIssuer(t, privateKey, "invalid-issuer"),
            expectedStatus: http.StatusUnauthorized,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Create a mock HTTP request
            req, err := http.NewRequest("GET", "/test", nil)
            if err != nil {
                t.Fatal(err)
            }

            // Add the token to the Authorization header
            req.Header.Add("Authorization", "Bearer "+tt.token)

            // Create a mock HTTP response writer
            rr := httptest.NewRecorder()

            // Call the AuthMiddleware function
            authMiddleware := jwkAuthOptions.AuthMiddleware()
            authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, req)

            // Check if the response status code is as expected
            assert.Equal(t, tt.expectedStatus, rr.Code)
        })
    }
}

func createJwkKeysAndSet(t *testing.T) (jwk.Set, *rsa.PrivateKey) {
    // Generate a new RSA key pair
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }

    // Create a JWK from the RSA public key
    publicKey, err := jwk.FromRaw(privateKey.Public())
    if err != nil {
        t.Fatal(err)
    }

    // Set the JWK properties
    err = publicKey.Set(jwk.KeyIDKey, kidValue)
    if err != nil {
        t.Fatal(err)
    }
    err = publicKey.Set(jwk.AlgorithmKey, jwa.RS256)
    if err != nil {
        t.Fatal(err)
    }
    err = publicKey.Set(jwk.KeyUsageKey, jwk.ForSignature)
    if err != nil {
        t.Fatal(err)
    }
    err = publicKey.Set(jwk.KeyTypeKey, jwa.RSA)
    if err != nil {
        t.Fatal(err)
    }

    // Create a JWK Set and add the JWK to it
    jwkSet := jwk.NewSet()
    err = jwkSet.AddKey(publicKey)
    if err != nil {
        t.Fatal(err)
    }

    return jwkSet, privateKey
}

func createValidToken(t *testing.T, privateKey *rsa.PrivateKey) string {
    token := jwt.New()
    setCommonClaims(t, token)
    return signToken(t, token, privateKey, createHeaders(t, kidValue))
}

func createTokenWithExpiration(t *testing.T, privateKey *rsa.PrivateKey, exp time.Time) string {
    token := jwt.New()
    setCommonClaims(t, token)
    err := token.Set(jwt.ExpirationKey, exp)
    if err != nil {
        t.Fatal(err)
    }

    return signToken(t, token, privateKey, createHeaders(t, kidValue))
}

func createTokenWithNotBefore(t *testing.T, privateKey *rsa.PrivateKey, nbf time.Time) string {
    token := jwt.New()
    setCommonClaims(t, token)
    err := token.Set(jwt.NotBeforeKey, nbf)
    if err != nil {
        t.Fatal(err)
    }
    return signToken(t, token, privateKey, createHeaders(t, kidValue))
}

func createTokenWithKid(t *testing.T, privateKey *rsa.PrivateKey, kid string) string {
    token := jwt.New()
    setCommonClaims(t, token)
    err := token.Set(jwk.KeyIDKey, kid)
    if err != nil {
        t.Fatal(err)
    }
    return signToken(t, token, privateKey, createHeaders(t, "invalid-kid"))
}

func createTokenWithIssuer(t *testing.T, privateKey *rsa.PrivateKey, iss string) string {
    token := jwt.New()
    setCommonClaims(t, token)
    err := token.Set(jwt.IssuerKey, iss)
    if err != nil {
        t.Fatal(err)
    }
    return signToken(t, token, privateKey, createHeaders(t, kidValue))
}

func setCommonClaims(t *testing.T, token jwt.Token) {
    err := token.Set(jwt.AudienceKey, audienceValue)
    if err != nil {
        t.Fatal(err)
    }
    err = token.Set(jwt.IssuerKey, issuerValue)
    if err != nil {
        t.Fatal(err)
    }
    err = token.Set(jwt.SubjectKey, subjectValue)
    if err != nil {
        t.Fatal(err)
    }
    err = token.Set(jwt.IssuedAtKey, time.Now())
    if err != nil {
        t.Fatal(err)
    }
    err = token.Set(jwt.JwtIDKey, tokenIdValue)
    if err != nil {
        t.Fatal(err)
    }
}

func createHeaders(t *testing.T, kid string) jws.Headers {
    headers := jws.NewHeaders()
    err := headers.Set(jwk.KeyIDKey, kid)
    if err != nil {
        t.Fatal(err)
    }
    return headers
}

func signToken(t *testing.T, token jwt.Token, privateKey *rsa.PrivateKey, headers jws.Headers) string {
    buf, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, privateKey, jws.WithProtectedHeaders(headers)))
    if err != nil {
        t.Fatal(err)
    }

    return string(buf)
}
