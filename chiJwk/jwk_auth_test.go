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

func TestAuthMiddlewareWithInvalidToken(t *testing.T) {
    // Create a mock HTTP request
    req, err := http.NewRequest("GET", "/test", nil)
    if err != nil {
        t.Fatal(err)
    }

    // Add an invalid Authorization header to the request
    req.Header.Add("Authorization", "Bearer invalid-token")

    // Create a mock HTTP response writer
    rr := httptest.NewRecorder()

    // Create a mock JwkAuthOptions
    jwkAuthOptions := &chiJwk.JwkAuthOptions{
        JwkSet:   jwk.NewSet(),
        Issuer:   "mock-issuer",
        Verifier: &chiJwk.GenericTokenVerifier{},
    }

    // Call the AuthMiddleware function
    authMiddleware := chiJwk.AuthMiddleware(jwkAuthOptions)
    authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rr, req)

    // Check if the response status code is 401 Unauthorized
    assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestVerifyToken(t *testing.T) {
    // Create a new JWK Set and JWK key
    jwkSet, privateKey := createJwkKeysAndSet(t)

    // Create a valid signed token
    signedToken := createValidToken(t, privateKey)

    // Create a new HTTP request
    req, err := http.NewRequest("GET", "/test", nil)
    if err != nil {
        t.Fatal(err)
    }

    // Add the signed token to the Authorization header
    req.Header.Add("Authorization", "Bearer "+signedToken)

    // Create a new JwkAuthOptions with the JWK Set and the issuer
    jwkAuthOptions := &chiJwk.JwkAuthOptions{
        JwkSet:   jwkSet,
        Issuer:   issuerValue,
        Verifier: &chiJwk.GenericTokenVerifier{},
    }

    // Call the VerifyToken method
    claims, err := jwkAuthOptions.Verifier.VerifyToken(req, jwkAuthOptions)
    if err != nil {
        t.Fatal(err)
    }

    // Assert the returned claims
    assert.Equal(t, "my-audience", claims[jwt.AudienceKey].([]string)[0])
    assert.Equal(t, issuerValue, claims[jwt.IssuerKey])
    assert.Equal(t, "my-subject", claims[jwt.SubjectKey])
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

    err := token.Set(jwt.AudienceKey, "my-audience")
    if err != nil {
        t.Fatal(err)
    }
    err = token.Set(jwt.IssuerKey, issuerValue)
    if err != nil {
        t.Fatal(err)
    }
    err = token.Set(jwt.SubjectKey, "my-subject")
    if err != nil {
        t.Fatal(err)
    }
    err = token.Set(jwt.IssuedAtKey, time.Now())
    if err != nil {
        t.Fatal(err)
    }
    err = token.Set(jwt.ExpirationKey, time.Now().Add(time.Minute*5))
    if err != nil {
        t.Fatal(err)
    }
    err = token.Set(jwt.NotBeforeKey, time.Now())
    if err != nil {
        t.Fatal(err)
    }
    err = token.Set(jwt.JwtIDKey, "unique-token-id")
    if err != nil {
        t.Fatal(err)
    }

    headers := jws.NewHeaders()
    err = headers.Set(jwk.KeyIDKey, kidValue)
    if err != nil {
        t.Fatal(err)
    }
    buf, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, privateKey, jws.WithProtectedHeaders(headers)))
    if err != nil {
        t.Fatal(err)
    }

    return string(buf)
}
