package provider

import (
	"crypto/ecdsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
)

func TestNewAuthES256(t *testing.T) {
	keyType := "ES256"
	expectedCurve := "P-256"
	expectedMethod := jwt.SigningMethodES256
	expectedUse := "testing"
	expectedOps := []string{"testing, foo"}

	testAuth, err := NewMockAuth(keyType, expectedUse, expectedOps)
	if err != nil {
		t.Fatalf("error creating test mock auth provider: %s\n", err)
	}

	if key, ok := testAuth.Key.(*ecdsa.PrivateKey); ok {
		if key.Params().Name != expectedCurve {
			t.Errorf("bad curve name, wanted: %q, got: %q", expectedCurve, key.Params().Name)
		}
	} else {
		t.Errorf("bad key type, got: '%T', wanted: '%T'", key, &ecdsa.PrivateKey{})
	}

	if len(testAuth.KeyResponse.Keys) != 1 {
		t.Errorf("bad key response list length, should be 1 but got %d", len(testAuth.KeyResponse.Keys))
		if len(testAuth.KeyResponse.Keys) < 1 {
			t.Fatalf("no keys in key list")
		}
	}
	key := testAuth.KeyResponse.Keys[0]

	if key.Algorithm != keyType {
		t.Errorf("bad key type returned, wanted: %q, got: %q", keyType, key.Algorithm)
	}
	if key.Use != expectedUse {
		t.Errorf("bad use returned, wanted: %q, got: %q", expectedUse, key.Use)
	}
	if diff := cmp.Diff(key.KeyOps, expectedOps); diff != "" {
		t.Errorf("bad key_ops returned:\n%s", diff)
	}

	if len(key.X) < 1 {
		t.Errorf("bad key X field, should have a length but got: %q", key.X)
	}
	if len(key.Y) < 1 {
		t.Errorf("bad key Y field, should have a length but got: %q", key.X)
	}

	if testAuth.SigningMethod != expectedMethod {
		t.Errorf("bad signing method found, wanted: %q, got: %q", expectedMethod.Name, testAuth.SigningMethod)
	}
}

func TestNewAuthES384(t *testing.T) {
	keyType := "ES384"
	expectedCurve := "P-384"
	expectedMethod := jwt.SigningMethodES384
	expectedUse := "testing"
	expectedOps := []string{"testing, foo"}

	testAuth, err := NewMockAuth(keyType, expectedUse, expectedOps)
	if err != nil {
		t.Fatalf("error creating test mock auth provider: %s\n", err)
	}

	if key, ok := testAuth.Key.(*ecdsa.PrivateKey); ok {
		if key.Params().Name != expectedCurve {
			t.Errorf("bad curve name, wanted: %q, got: %q", expectedCurve, key.Params().Name)
		}
	} else {
		t.Errorf("bad key type, got: '%T', wanted: '%T'", key, &ecdsa.PrivateKey{})
	}

	if len(testAuth.KeyResponse.Keys) != 1 {
		t.Errorf("bad key response list length, should be 1 but got %d", len(testAuth.KeyResponse.Keys))
		if len(testAuth.KeyResponse.Keys) < 1 {
			t.Fatalf("no keys in key list")
		}
	}
	key := testAuth.KeyResponse.Keys[0]

	if key.Algorithm != keyType {
		t.Errorf("bad key type returned, wanted: %q, got: %q", keyType, key.Algorithm)
	}
	if key.Use != expectedUse {
		t.Errorf("bad use returned, wanted: %q, got: %q", expectedUse, key.Use)
	}
	if diff := cmp.Diff(key.KeyOps, expectedOps); diff != "" {
		t.Errorf("bad key_ops returned:\n%s", diff)
	}

	if len(key.X) < 1 {
		t.Errorf("bad key X field, should have a length but got: %q", key.X)
	}
	if len(key.Y) < 1 {
		t.Errorf("bad key Y field, should have a length but got: %q", key.X)
	}

	if testAuth.SigningMethod != expectedMethod {
		t.Errorf("bad signing method found, wanted: %q, got: %q", expectedMethod.Name, testAuth.SigningMethod)
	}
}

func TestNewAuthES512(t *testing.T) {
	keyType := "ES512"
	expectedCurve := "P-521"
	expectedMethod := jwt.SigningMethodES512
	expectedUse := "testing"
	expectedOps := []string{"testing, foo"}

	testAuth, err := NewMockAuth(keyType, expectedUse, expectedOps)
	if err != nil {
		t.Fatalf("error creating test mock auth provider: %s\n", err)
	}

	if key, ok := testAuth.Key.(*ecdsa.PrivateKey); ok {
		if key.Params().Name != expectedCurve {
			t.Errorf("bad curve name, wanted: %q, got: %q", expectedCurve, key.Params().Name)
		}
	} else {
		t.Errorf("bad key type, got: '%T', wanted: '%T'", key, &ecdsa.PrivateKey{})
	}

	if len(testAuth.KeyResponse.Keys) != 1 {
		t.Errorf("bad key response list length, should be 1 but got %d", len(testAuth.KeyResponse.Keys))
		if len(testAuth.KeyResponse.Keys) < 1 {
			t.Fatalf("no keys in key list")
		}
	}
	key := testAuth.KeyResponse.Keys[0]

	if key.Algorithm != keyType {
		t.Errorf("bad key type returned, wanted: %q, got: %q", keyType, key.Algorithm)
	}
	if key.Use != expectedUse {
		t.Errorf("bad use returned, wanted: %q, got: %q", expectedUse, key.Use)
	}
	if diff := cmp.Diff(key.KeyOps, expectedOps); diff != "" {
		t.Errorf("bad key_ops returned:\n%s", diff)
	}

	if len(key.X) < 1 {
		t.Errorf("bad key X field, should have a length but got: %q", key.X)
	}
	if len(key.Y) < 1 {
		t.Errorf("bad key Y field, should have a length but got: %q", key.X)
	}

	if testAuth.SigningMethod != expectedMethod {
		t.Errorf("bad signing method found, wanted: %q, got: %q", expectedMethod.Name, testAuth.SigningMethod)
	}
}
