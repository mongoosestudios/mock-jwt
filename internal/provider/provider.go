package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

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

func NewMockAuth(signMethod string, keyUse string, keyOps []string) (*MockAuth, error) {
	thisMethod, privateKey, webKey, err := generateNewPrivateKey(signMethod)
	if err != nil {
		return nil, fmt.Errorf("error generating new private key: %s", err)
	}

	webKey.Use = keyUse
	webKey.KeyOps = keyOps

	keySet := KeysetResponse{Keys: []JSONWebKey{
		webKey,
	}}

	return &MockAuth{
		SigningMethod: thisMethod,
		Key:           privateKey,
		KeyResponse:   keySet,
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

func generateNewPrivateKey(signingMethod string) (jwt.SigningMethod, interface{}, JSONWebKey, error) {
	var privateKey interface{}
	newJWK := JSONWebKey{
		KeyID: uuid.New(),
	}
	var thisMethod jwt.SigningMethod

	switch strings.ToLower(signingMethod) {
	case "es256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, newJWK, fmt.Errorf("error generating private key: %s", err)
		}
		keyX := base64.URLEncoding.EncodeToString(k.PublicKey.Params().Gx.Bytes())
		keyY := base64.URLEncoding.EncodeToString(k.PublicKey.Params().Gy.Bytes())

		privateKey = k

		thisMethod = jwt.SigningMethodES256
		newJWK.Algorithm = "ES256"
		newJWK.Curve = k.Params().Name
		newJWK.X = keyX
		newJWK.Y = keyY

	case "es384":
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, newJWK, fmt.Errorf("error generating private key: %s", err)
		}
		keyX := base64.URLEncoding.EncodeToString(k.PublicKey.Params().Gx.Bytes())
		keyY := base64.URLEncoding.EncodeToString(k.PublicKey.Params().Gy.Bytes())

		privateKey = k

		thisMethod = jwt.SigningMethodES384
		newJWK.Algorithm = "ES384"
		newJWK.Curve = k.Params().Name
		newJWK.X = keyX
		newJWK.Y = keyY
	case "es512":
		// this is confusing because 521/512 but accurate to the RFC as far as I can tell
		// https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
		k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, nil, newJWK, fmt.Errorf("error generating private key: %s", err)
		}
		keyX := base64.URLEncoding.EncodeToString(k.PublicKey.Params().Gx.Bytes())
		keyY := base64.URLEncoding.EncodeToString(k.PublicKey.Params().Gy.Bytes())

		privateKey = k

		thisMethod = jwt.SigningMethodES512
		newJWK.Algorithm = "ES512"
		newJWK.Curve = k.Params().Name
		newJWK.X = keyX
		newJWK.Y = keyY
	default:
		return nil, nil, newJWK, fmt.Errorf("unsupported signing method: %s", signingMethod)
	}

	return thisMethod, privateKey, newJWK, nil
}
