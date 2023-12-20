package chiJwk_test

import (
    "crypto/rand"
    "crypto/rsa"
    "encoding/json"
    "fmt"
    "testing"

    "github.com/lestrrat-go/jwx/v2/jwa"
    "github.com/lestrrat-go/jwx/v2/jwk"
    "github.com/lestrrat-go/jwx/v2/jwt"
)

func TestVerifyToken(t *testing.T) {
    // Generate a new RSA key pair
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }

    // Create a JWK from the RSA key
    jwkKey, err := jwk.FromRaw(key)
    if err != nil {
        t.Fatal(err)
    }

    // Set the key ID (kid)
    jwkKey.Set("kid", "my-key-id")

    // Create a JWK Set and add the JWK to it
    jwkSet := jwk.NewSet()
    jwkSet.AddKey(jwkKey)

    // Convert the JWK Set to JSON
    jwkSetJSON, err := json.Marshal(jwkSet)
    if err != nil {
        t.Fatal(err)
    }

    // Print the JWK Set JSON
    fmt.Println(string(jwkSetJSON))

    fmt.Println("")
    fmt.Println("")

    // Create a JWT token
    token := jwt.New()
    token.Set(jwt.AudienceKey, "my-audience")
    token.Set(jwt.IssuerKey, "my-issuer")
    token.Set(jwt.SubjectKey, "my-subject")

    signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, jwkKey))
    if err != nil {
        t.Fatal(err)
    }

    fmt.Println(string(signedToken))
}
