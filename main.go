package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type server struct {
	signingMethod jwt.SigningMethod
	key           interface{}
	keyResponse   KeysetResponse
}

// JSONWebKey is the key format described at https://datatracker.ietf.org/doc/html/rfc7517#section-3
type JSONWebKey struct {
	KeyType              string    `json:"kty"`
	Use                  string    `json:"use"`
	KeyOps               []string  `json:"key_ops,omitempty"`
	Algorithm            string    `json:"alg,omitempty"`
	KeyID                uuid.UUID `json:"kid,omitempty"`
	X509URL              string    `json:"x5u,omitempty"`
	X509Chain            []string  `json:"x5c,omitempty"`      // N.B. these should be b64 encoded strings if used
	X509ThumbprintSHA1   string    `json:"x5t,omitempty"`      // N.B. B64 uRL encoded SHA-1 thumbprint of DER encoding
	X509ThumbprintSHA256 string    `json:"x5t#S256,omitempty"` // N.B. B64 URL encoded SHA-256 thumbprint of DER encoding
	Curve                string    `json:"crv,omitempty"`      // N.B. not directly specified in the RFC but present in examples
	X                    string    `json:"x,omitempty"`        // N.B. B64 URL encoded x coordinate of ECC, not directly specified in the RFC, but present in examples
	Y                    string    `json:"y,omitempty"`        // N.B. B64 URL encoded y coordinate of ECC, not directly specified in the RFC, but present in examples
}

type KeysetResponse struct {
	Keys []JSONWebKey `json:"keys"`
}

func main() {
	var ipFlag = flag.String("ip", "", "the IP interfaces to bind to, default is all interfaces on the port specified (IE: \":8080\")")
	var portFlag = flag.Int("port", 8080, "the port to listen on")
	var rootURL = flag.String("root", "auth", "the root URL to serve tokens on")
	var JWKSURL = flag.String("jwks-url", ".well-known", "the URL that the JWKS data will be served at")
	var JWKSName = flag.String("jwks-name", "jwks.json", "name and extension that the JWKS data will be served at")

	flag.Parse()

	// TODO: needs a flag to set the signing method with available options in help
	// TODO: pull this out into a function that we can call in a switch based on ^
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		slog.Error("error generating private key", "err", err)
		os.Exit(1)
	}

	keyX := base64.URLEncoding.EncodeToString(privateKey.PublicKey.Params().Gx.Bytes())
	keyY := base64.URLEncoding.EncodeToString(privateKey.PublicKey.Params().Gy.Bytes())

	keyset := KeysetResponse{Keys: []JSONWebKey{
		{
			KeyType:   "EC",
			Use:       "sig",
			KeyOps:    []string{"verify"},
			Algorithm: "ES256",
			KeyID:     uuid.New(),
			Curve:     "P-256",
			X:         keyX,
			Y:         keyY,
		},
	}}

	srv := server{
		signingMethod: jwt.SigningMethodES256,
		key:           privateKey,
		keyResponse:   keyset,
	}

	// TODO allow for setting the path in a flag
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) { return })
	mux.HandleFunc(fmt.Sprintf("POST /%s", *rootURL), srv.handleAuth)
	mux.HandleFunc(fmt.Sprintf("GET /%s/%s/%s", *rootURL, *JWKSURL, *JWKSName), srv.handleWellKnown)

	httpServer := http.Server{
		Addr:    fmt.Sprintf("%s:%d", *ipFlag, *portFlag),
		Handler: mux,
	}

	go func() {
		slog.Info("Server starting, listening on", "ip", "all", "port", "8888")
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Server error", "err", err)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

		<-sigChan
		slog.Info("Shutting down server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := httpServer.Shutdown(shutdownCtx)
		if err != nil {
			slog.Error("error shutting down server", "err", err)
		}
	}()
	wg.Wait()
}

func (s *server) handleAuth(w http.ResponseWriter, r *http.Request) {
	// TODO: try to parse the body, if we get a map set the custom claims
	token := jwt.New(s.signingMethod)
	signedString, err := token.SignedString(s.key)
	if err != nil {
		http.Error(w, fmt.Sprintf("error creating signed string: %s\n", err), http.StatusInternalServerError)
		return
	}

	_, err = w.Write([]byte(signedString))
	if err != nil {
		slog.Error("error writing response", "err", err)
	}
}

func (s *server) handleWellKnown(w http.ResponseWriter, r *http.Request) {
	marshalled, err := json.Marshal(s.keyResponse)
	if err != nil {
		http.Error(w, fmt.Sprintf("error marshalling key response: %s", err), http.StatusInternalServerError)
		return
	}

	_, err = w.Write(marshalled)
	if err != nil {
		slog.Error("error writing well known response body", "err", err)
	}

	return
}
