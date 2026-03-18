package provider

import (
	"crypto/ecdsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
)

func TestNewAuthES256(t *testing.T) {
	signingMethod := "ES256"
	expectedKeyType := "EC"
	expectedCurve := "P-256"
	expectedMethod := jwt.SigningMethodES256
	expectedUse := "testing"
	expectedOps := []string{"testing, foo"}

	testAuth, err := NewMockAuth(signingMethod, expectedUse, expectedOps)
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

	if key.Algorithm != signingMethod {
		t.Errorf("bad key type returned, wanted: %q, got: %q", signingMethod, key.Algorithm)
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

	if key.KeyType != expectedKeyType {
		t.Errorf("bad key type set, wanted: %q, got: %q", expectedKeyType, key.KeyType)
	}

	if testAuth.SigningMethod != expectedMethod {
		t.Errorf("bad signing method found, wanted: %q, got: %q", expectedMethod.Name, testAuth.SigningMethod)
	}
}

func TestNewAuthES384(t *testing.T) {
	signingMethod := "ES384"
	expectedKeyType := "EC"
	expectedCurve := "P-384"
	expectedMethod := jwt.SigningMethodES384
	expectedUse := "testing"
	expectedOps := []string{"testing, foo"}

	testAuth, err := NewMockAuth(signingMethod, expectedUse, expectedOps)
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

	if key.Algorithm != signingMethod {
		t.Errorf("bad key type returned, wanted: %q, got: %q", signingMethod, key.Algorithm)
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

	if key.KeyType != expectedKeyType {
		t.Errorf("bad key type set, wanted: %q, got: %q", expectedKeyType, key.KeyType)
	}

	if testAuth.SigningMethod != expectedMethod {
		t.Errorf("bad signing method found, wanted: %q, got: %q", expectedMethod.Name, testAuth.SigningMethod)
	}
}

func TestNewAuthES512(t *testing.T) {
	signingMethod := "ES512"
	expectedKeyType := "EC"
	expectedCurve := "P-521"
	expectedMethod := jwt.SigningMethodES512
	expectedUse := "testing"
	expectedOps := []string{"testing, foo"}

	testAuth, err := NewMockAuth(signingMethod, expectedUse, expectedOps)
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

	if key.Algorithm != signingMethod {
		t.Errorf("bad key type returned, wanted: %q, got: %q", signingMethod, key.Algorithm)
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

	if key.KeyType != expectedKeyType {
		t.Errorf("bad key type set, wanted: %q, got: %q", expectedKeyType, key.KeyType)
	}

	if testAuth.SigningMethod != expectedMethod {
		t.Errorf("bad signing method found, wanted: %q, got: %q", expectedMethod.Name, testAuth.SigningMethod)
	}
}

func TestTokenES256(t *testing.T) {
	signingMethod := "ES256"
	expectedUse := "testing"
	expectedOps := []string{"testing, foo"}

	testAuth, err := NewMockAuth(signingMethod, expectedUse, expectedOps)
	if err != nil {
		t.Fatalf("error creating test mock auth provider: %s\n", err)
	}

	testClaims := jwt.MapClaims{
		"claimA": "A",
		"claimB": "B",
	}

	token, err := testAuth.MakeSignedToken(testClaims)
	if err != nil {
		t.Fatalf("error creating token: %s", err)
	}

	testParser := createParser([]string{jwt.SigningMethodES256.Alg()})
	parsedToken, err := testParser.ParseWithClaims(token, &testClaims, func(token *jwt.Token) (any, error) {
		return &testAuth.Key.(*ecdsa.PrivateKey).PublicKey, nil
	})
	if err != nil {
		t.Fatalf("error validating token: %s\n", err)
	}

	if !parsedToken.Valid {
		t.Error("unable to validate parsed token using the public key")
	}

	tokenClaims := parsedToken.Claims.(*jwt.MapClaims)
	if claimA, ok := (*tokenClaims)["claimA"]; ok {
		if claimA != testClaims["claimA"] {
			t.Errorf("test claim A not passed through signed token correctly, wanted: %s, got: %s",
				testClaims["claimA"], claimA)
		}
	} else {
		t.Errorf("test claim A not passed through signed token correctly, not present in map")
	}
	if claimB, ok := (*tokenClaims)["claimB"]; ok {
		if claimB != testClaims["claimB"] {
			t.Errorf("test claim B not passed through signed token correctly, wanted: %s, got: %s",
				testClaims["claimB"], claimB)
		}
	} else {
		t.Errorf("test claim B not passed through signed token correctly, not present in map")
	}
}

func TestTokenES384(t *testing.T) {
	signingMethod := "ES384"
	expectedUse := "testing"
	expectedOps := []string{"testing, foo"}

	testAuth, err := NewMockAuth(signingMethod, expectedUse, expectedOps)
	if err != nil {
		t.Fatalf("error creating test mock auth provider: %s\n", err)
	}

	testClaims := jwt.MapClaims{
		"claimA": "A",
		"claimB": "B",
	}

	token, err := testAuth.MakeSignedToken(testClaims)
	if err != nil {
		t.Fatalf("error creating token: %s", err)
	}

	testParser := createParser([]string{jwt.SigningMethodES384.Alg()})
	parsedToken, err := testParser.ParseWithClaims(token, &testClaims, func(token *jwt.Token) (any, error) {
		return &testAuth.Key.(*ecdsa.PrivateKey).PublicKey, nil
	})
	if err != nil {
		t.Fatalf("error validating token: %s\n", err)
	}

	if !parsedToken.Valid {
		t.Error("unable to validate parsed token using the public key")
	}

	tokenClaims := parsedToken.Claims.(*jwt.MapClaims)
	if claimA, ok := (*tokenClaims)["claimA"]; ok {
		if claimA != testClaims["claimA"] {
			t.Errorf("test claim A not passed through signed token correctly, wanted: %s, got: %s",
				testClaims["claimA"], claimA)
		}
	} else {
		t.Errorf("test claim A not passed through signed token correctly, not present in map")
	}
	if claimB, ok := (*tokenClaims)["claimB"]; ok {
		if claimB != testClaims["claimB"] {
			t.Errorf("test claim B not passed through signed token correctly, wanted: %s, got: %s",
				testClaims["claimB"], claimB)
		}
	} else {
		t.Errorf("test claim B not passed through signed token correctly, not present in map")
	}
}

func TestTokenES512(t *testing.T) {
	signingMethod := "ES512"
	expectedUse := "testing"
	expectedOps := []string{"testing, foo"}

	testAuth, err := NewMockAuth(signingMethod, expectedUse, expectedOps)
	if err != nil {
		t.Fatalf("error creating test mock auth provider: %s\n", err)
	}

	testClaims := jwt.MapClaims{
		"claimA": "A",
		"claimB": "B",
	}

	token, err := testAuth.MakeSignedToken(testClaims)
	if err != nil {
		t.Fatalf("error creating token: %s", err)
	}

	testParser := createParser([]string{jwt.SigningMethodES512.Alg()})
	parsedToken, err := testParser.ParseWithClaims(token, &testClaims, func(token *jwt.Token) (any, error) {
		return &testAuth.Key.(*ecdsa.PrivateKey).PublicKey, nil
	})
	if err != nil {
		t.Fatalf("error validating token: %s\n", err)
	}

	if !parsedToken.Valid {
		t.Error("unable to validate parsed token using the public key")
	}

	tokenClaims := parsedToken.Claims.(*jwt.MapClaims)
	if claimA, ok := (*tokenClaims)["claimA"]; ok {
		if claimA != testClaims["claimA"] {
			t.Errorf("test claim A not passed through signed token correctly, wanted: %s, got: %s",
				testClaims["claimA"], claimA)
		}
	} else {
		t.Errorf("test claim A not passed through signed token correctly, not present in map")
	}
	if claimB, ok := (*tokenClaims)["claimB"]; ok {
		if claimB != testClaims["claimB"] {
			t.Errorf("test claim B not passed through signed token correctly, wanted: %s, got: %s",
				testClaims["claimB"], claimB)
		}
	} else {
		t.Errorf("test claim B not passed through signed token correctly, not present in map")
	}
}

func createParser(methods []string) *jwt.Parser {
	return jwt.NewParser(
		jwt.WithStrictDecoding(),
		jwt.WithValidMethods(methods),
	)
}
