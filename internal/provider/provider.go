package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type MockAuth struct {
	SigningMethod jwt.SigningMethod
	Key           interface{}
	KeyResponse   KeysetResponse
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

func NewMockAuth() (*MockAuth, error) {
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

	return &MockAuth{
		SigningMethod: jwt.SigningMethodES256,
		Key:           privateKey,
		KeyResponse:   keyset,
	}, nil
}

func (ma *MockAuth) MakeSignedToken(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(ma.SigningMethod, claims)
	signedString, err := token.SignedString(ma.Key)
	if err != nil {
		return "", err
	}
	return signedString, nil
}

func (ma *MockAuth) GetKey() KeysetResponse {
	return ma.KeyResponse
}
