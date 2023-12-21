package chiJwk

import (
    "context"
    crypto "crypto/rand"
    "crypto/rsa"
    "encoding/json"
    "math/rand"
    "net"
    "net/http"
    "strconv"
    "time"

    "github.com/lestrrat-go/jwx/v2/jwa"
    "github.com/lestrrat-go/jwx/v2/jwk"
    "github.com/lestrrat-go/jwx/v2/jws"
    "github.com/lestrrat-go/jwx/v2/jwt"
)

const kidValue = "test-kid"

type TestServer struct {
    JwkSet     jwk.Set
    PrivateKey *rsa.PrivateKey
    Issuer     string
    Server     *http.Server
    Kid        string
}

// NewTestServer creates a new test server with a JWK Set and RSA key pair.
// The server will listen on the specified address.
// If no address is specified, the server will listen on a random port.
// The server can be stopped by calling the Stop method.
//
// The JWK Set will contain a single JWK with the following properties:
// - Key ID: test-kid
// - Algorithm: RS256
// - Key Usage: Signature
// - Key Type: RSA
//
// The RSA key pair will be used to sign JWTs.
//
// The Issuer property will be set to the address of the server.
//
// The Kid property will be set to the Key ID of the JWK.
//
// The server will have two endpoints:
// - /keys: Returns the JWK Set
// - /issue: Issues a signed JWT with the claims specified in the request body
func NewTestServer(addr string) (*TestServer, error) {
    // Generate a new RSA key pair
    privateKey, err := rsa.GenerateKey(crypto.Reader, 2048)
    if err != nil {
        return nil, err
    }

    // Create a JWK from the public key
    publicKey, err := jwk.FromRaw(privateKey.Public())
    if err != nil {
        return nil, err
    }

    // Set the JWK properties
    err = publicKey.Set(jwk.KeyIDKey, kidValue)
    if err != nil {
        return nil, err
    }
    err = publicKey.Set(jwk.AlgorithmKey, jwa.RS256)
    if err != nil {
        return nil, err
    }
    err = publicKey.Set(jwk.KeyUsageKey, jwk.ForSignature)
    if err != nil {
        return nil, err
    }
    err = publicKey.Set(jwk.KeyTypeKey, jwa.RSA)
    if err != nil {
        return nil, err
    }

    // Create a JWK Set and add the JWK to it
    jwkSet := jwk.NewSet()
    err = jwkSet.AddKey(publicKey)
    if err != nil {
        return nil, err
    }

    server := &TestServer{
        JwkSet:     jwkSet,
        PrivateKey: privateKey,
        Server:     &http.Server{},
    }

    err = server.start(addr)
    if err != nil {
        return nil, err
    }

    return server, nil
}

// Stop stops the test server.
func (s *TestServer) Stop(ctx context.Context) {
    _ = s.Server.Shutdown(ctx)
}

func (s *TestServer) start(addr string) error {
    http.HandleFunc("/keys", s.handleJwkSet)
    http.HandleFunc("/issue", s.handleIssueKeys)

    // If no address is specified, listen on a random port
    if addr == "" {
        rand.New(rand.NewSource(time.Now().UnixNano()))
        port := rand.Intn(16384) + 49152
        addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
    }

    listener, err := net.Listen("tcp", addr)
    if err != nil {
        return err
    }

    s.Server.Addr = addr
    s.Issuer = "http://" + addr
    go func() {
        _ = s.Server.Serve(listener)
    }()
    return nil
}

func (s *TestServer) handleJwkSet(w http.ResponseWriter, r *http.Request) {
    _ = json.NewEncoder(w).Encode(s.JwkSet)
}

func (s *TestServer) handleIssueKeys(w http.ResponseWriter, r *http.Request) {
    var claims map[string]interface{}
    err := json.NewDecoder(r.Body).Decode(&claims)
    if err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    token := jwt.New()
    for key, value := range claims {
        _ = token.Set(key, value)
    }

    // Set common claims
    err = token.Set(jwt.AudienceKey, "test-audience")
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }
    err = token.Set(jwt.IssuerKey, s.Issuer)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }
    err = token.Set(jwt.SubjectKey, "test-subject")
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }
    err = token.Set(jwt.NotBeforeKey, time.Now())
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }
    err = token.Set(jwt.IssuedAtKey, time.Now())
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }
    err = token.Set(jwt.ExpirationKey, time.Now().Add(time.Minute))
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }
    err = token.Set(jwt.JwtIDKey, "test-token-id")
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }

    headers := jws.NewHeaders()
    err = headers.Set(jwk.KeyIDKey, kidValue)
    if err != nil {
        return
    }

    buf, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, s.PrivateKey, jws.WithProtectedHeaders(headers)))
    _, err = w.Write(buf)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }
}