package main

import (
	"context"
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

	"github.com/MongooseStudios/mock-jwt/internal/provider"
	"github.com/golang-jwt/jwt/v5"
)

type server struct {
	auth *provider.MockAuth
}

func main() {
	var ipFlag = flag.String("ip", "", "the IP interfaces to bind to, default is all interfaces on the port specified (IE: \":8080\")")
	var portFlag = flag.Int("port", 8080, "the port to listen on")
	var rootURL = flag.String("root", "auth", "the root URL to serve tokens on")
	var JWKSURL = flag.String("jwks-url", ".well-known", "the URL that the JWKS data will be served at")
	var JWKSName = flag.String("jwks-name", "jwks.json", "name and extension that the JWKS data will be served at")

	flag.Parse()

	mockProvider, err := provider.NewMockAuth()
	if err != nil {
		slog.Error("error creating mock auth provider", "err", err)
		os.Exit(1)
	}

	srv := server{
		auth: mockProvider,
	}

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

		err = httpServer.Shutdown(shutdownCtx)
		if err != nil {
			slog.Error("error shutting down server", "err", err)
		}
	}()
	wg.Wait()
}

func (s *server) handleAuth(w http.ResponseWriter, r *http.Request) {
	claims := make(jwt.MapClaims)

	// unmarshall the body into a map that will echo the claims provided (if there are any) back through the token claims
	if r.ContentLength > 0 {
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&claims)
		if err != nil {
			http.Error(w, fmt.Sprintf("error unmarshalling request body to claims: %s\n", err), http.StatusBadRequest)
			return
		}
	}

	newToken, err := s.auth.MakeSignedToken(claims)
	if err != nil {
		http.Error(w, fmt.Sprintf("error generating token: %s\n", err), http.StatusInternalServerError)
		return
	}

	_, err = w.Write([]byte(newToken))
	if err != nil {
		slog.Error("error writing response", "err", err)
	}
}

func (s *server) handleWellKnown(w http.ResponseWriter, _ *http.Request) {
	marshalled, err := json.Marshal(s.auth.GetKey())
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
