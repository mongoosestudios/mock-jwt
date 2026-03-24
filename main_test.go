package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/mongoosestudios/mock-jwt/internal/provider"
)

func TestHandleAuth(t *testing.T) {
	testProvider, err := provider.NewMockAuth("es256", "sig", []string{"verify"})
	if err != nil {
		t.Fatalf("error creating mock auth provider: %s\n", err)
	}

	testServer := server{
		auth: testProvider,
	}

	testRequest := httptest.NewRequest(http.MethodPost, "/auth", nil)
	testRecorder := httptest.NewRecorder()

	testServer.handleAuth(testRecorder, testRequest)

	if testRecorder.Code != http.StatusOK {
		t.Errorf("error handling auth\nresponse code: %d\nbody: %s", testRecorder.Code, testRecorder.Body)
	}

	decoder := json.NewDecoder(testRecorder.Body)
	responseData := response{}
	err = decoder.Decode(&responseData)
	if err != nil {
		t.Fatalf("error unmarshalling response body: %s", err)
	}

	if len(responseData.Token) < 1 {
		t.Errorf("token  from response should have data, but got length <1\ndata: %+v\n", responseData)
	}
}

func TestHandleAuthWithClaims(t *testing.T) {
	testProvider, err := provider.NewMockAuth("es256", "sig", []string{"verify"})
	if err != nil {
		t.Fatalf("error creating mock auth provider: %s\n", err)
	}

	testServer := server{
		auth: testProvider,
	}

	testClaims := map[string]any{
		"foo": "foo",
		"bar": "bar",
		"foobar": map[string]any{
			"foobarA": "A",
			"foobarB": "B",
		},
	}

	marshalled, err := json.Marshal(testClaims)
	if err != nil {
		t.Fatalf("error marshalling test claims: %s\n", err)
	}

	testRequest := httptest.NewRequest(http.MethodPost, "/auth", bytes.NewBuffer(marshalled))
	testRecorder := httptest.NewRecorder()

	testServer.handleAuth(testRecorder, testRequest)

	if testRecorder.Code != http.StatusOK {
		t.Errorf("error handling auth\nresponse code: %d\nbody: %s", testRecorder.Code, testRecorder.Body)
	}

	decoder := json.NewDecoder(testRecorder.Body)
	responseData := response{}
	err = decoder.Decode(&responseData)
	if err != nil {
		t.Fatalf("error unmarshalling response body: %s", err)
	}

	if len(responseData.Token) < 1 {
		t.Fatalf("token  from response should have data, but got length <1\ndata: %+v\n", responseData)
	}

	// create a template to extract the token's claims into
	claimTemplate := map[string]any{
		"foo": "",
		"bar": "",
		"foobar": map[string]any{
			"foobarA": "",
			"foobarB": "",
		},
	}
	// convert to a mapClaims to make the parser happy
	var expectedClaims jwt.MapClaims
	expectedClaims = claimTemplate

	testParser := createParser([]string{jwt.SigningMethodES256.Alg()})
	testKey, err := testProvider.GetPublicKey()
	if err != nil {
		t.Fatalf("error getting mock auth provider public key: %s", err)
	}

	parsedToken, err := testParser.ParseWithClaims(responseData.Token, expectedClaims, func(token *jwt.Token) (any, error) {
		return testKey.(*ecdsa.PublicKey), nil
	})
	if err != nil {
		t.Fatalf("error validating token: %s\n", err)
	}

	if !parsedToken.Valid {
		t.Error("unable to validate parsed token using the public key")
	}

	// massage the types so we can directly compare.  Map Claims is just a map[string]any with extra steps
	var assertedClaims jwt.MapClaims
	assertedClaims = expectedClaims

	if diff := cmp.Diff(assertedClaims, parsedToken.Claims); diff != "" {
		t.Errorf("claims not passed back correctly\n%s\n", diff)
	}
}

func TestHandleAuthWithCustomClaims(t *testing.T) {
	testProvider, err := provider.NewMockAuth("es256", "sig", []string{"verify"})
	if err != nil {
		t.Fatalf("error creating mock auth provider: %s\n", err)
	}

	testServer := server{
		auth: testProvider,
	}

	testClaims := map[string]any{
		"foo": "foo",
		"bar": "bar",
		"foobar": map[string]any{
			"foobarA": "A",
			"foobarB": "B",
		},
	}

	marshalled, err := json.Marshal(testClaims)
	if err != nil {
		t.Fatalf("error marshalling test claims: %s\n", err)
	}

	testRequest := httptest.NewRequest(http.MethodPost, "/setclaims", bytes.NewBuffer(marshalled))
	testRecorder := httptest.NewRecorder()

	testServer.handleAddCustomClaims(testRecorder, testRequest)
	if testRecorder.Code != http.StatusOK {
		t.Fatalf("error setting custom claims\nresponse code: %d\nbody: %s", testRecorder.Code, testRecorder.Body)
	}

	testRequest = httptest.NewRequest(http.MethodPost, "/auth", nil)
	testRecorder = httptest.NewRecorder()

	testServer.handleAuth(testRecorder, testRequest)

	if testRecorder.Code != http.StatusOK {
		t.Errorf("error handling auth\nresponse code: %d\nbody: %s", testRecorder.Code, testRecorder.Body)
	}

	decoder := json.NewDecoder(testRecorder.Body)
	responseData := response{}
	err = decoder.Decode(&responseData)
	if err != nil {
		t.Fatalf("error unmarshalling response body: %s", err)
	}

	if len(responseData.Token) < 1 {
		t.Fatalf("token  from response should have data, but got length <1\ndata: %+v\n", responseData)
	}

	// create a template to extract the token's claims into
	claimTemplate := map[string]any{
		"foo": "",
		"bar": "",
		"foobar": map[string]any{
			"foobarA": "",
			"foobarB": "",
		},
	}
	// convert to a mapClaims to make the parser happy
	var expectedClaims jwt.MapClaims
	expectedClaims = claimTemplate

	testParser := createParser([]string{jwt.SigningMethodES256.Alg()})
	testKey, err := testProvider.GetPublicKey()
	if err != nil {
		t.Fatalf("error getting mock auth provider public key: %s", err)
	}

	parsedToken, err := testParser.ParseWithClaims(responseData.Token, expectedClaims, func(token *jwt.Token) (any, error) {
		return testKey.(*ecdsa.PublicKey), nil
	})
	if err != nil {
		t.Fatalf("error validating token: %s\n", err)
	}

	if !parsedToken.Valid {
		t.Error("unable to validate parsed token using the public key")
	}

	// massage the types so we can directly compare.  Map Claims is just a map[string]any with extra steps
	var assertedClaims jwt.MapClaims
	assertedClaims = expectedClaims

	if diff := cmp.Diff(assertedClaims, parsedToken.Claims); diff != "" {
		t.Errorf("claims not passed back correctly\n%s\n", diff)
	}
}

func TestHandleAuthWithCustomClaimsOverridden(t *testing.T) {
	testProvider, err := provider.NewMockAuth("es256", "sig", []string{"verify"})
	if err != nil {
		t.Fatalf("error creating mock auth provider: %s\n", err)
	}

	testServer := server{
		auth: testProvider,
	}

	testClaims := map[string]any{
		"foo": "foo",
		"bar": "bar",
		"foobar": map[string]any{
			"foobarA": "A",
			"foobarB": "B",
		},
	}

	marshalled, err := json.Marshal(testClaims)
	if err != nil {
		t.Fatalf("error marshalling test claims: %s\n", err)
	}

	testRequest := httptest.NewRequest(http.MethodPost, "/setclaims", bytes.NewBuffer(marshalled))
	testRecorder := httptest.NewRecorder()

	testServer.handleAddCustomClaims(testRecorder, testRequest)
	if testRecorder.Code != http.StatusOK {
		t.Fatalf("error setting custom claims\nresponse code: %d\nbody: %s", testRecorder.Code, testRecorder.Body)
	}

	requestClaims := map[string]any{
		"foobar": "barbaz",
	}
	marshalled, err = json.Marshal(requestClaims)
	if err != nil {
		t.Fatalf("error marshalling request claims: %s\n", err)
	}

	testRequest = httptest.NewRequest(http.MethodPost, "/auth", bytes.NewBuffer(marshalled))
	testRecorder = httptest.NewRecorder()

	testServer.handleAuth(testRecorder, testRequest)

	if testRecorder.Code != http.StatusOK {
		t.Errorf("error handling auth\nresponse code: %d\nbody: %s", testRecorder.Code, testRecorder.Body)
	}

	decoder := json.NewDecoder(testRecorder.Body)
	responseData := response{}
	err = decoder.Decode(&responseData)
	if err != nil {
		t.Fatalf("error unmarshalling response body: %s", err)
	}

	if len(responseData.Token) < 1 {
		t.Fatalf("token  from response should have data, but got length <1\ndata: %+v\n", responseData)
	}

	// create a template to extract the token's claims into
	claimTemplate := map[string]any{
		"foo":    "",
		"bar":    "",
		"foobar": "",
	}
	// convert to a mapClaims to make the parser happy
	var expectedClaims jwt.MapClaims
	expectedClaims = claimTemplate

	testParser := createParser([]string{jwt.SigningMethodES256.Alg()})
	testKey, err := testProvider.GetPublicKey()
	if err != nil {
		t.Fatalf("error getting mock auth provider public key: %s", err)
	}

	parsedToken, err := testParser.ParseWithClaims(responseData.Token, expectedClaims, func(token *jwt.Token) (any, error) {
		return testKey.(*ecdsa.PublicKey), nil
	})
	if err != nil {
		t.Fatalf("error validating token: %s\n", err)
	}

	if !parsedToken.Valid {
		t.Error("unable to validate parsed token using the public key")
	}

	// massage the types so we can directly compare.  Map Claims is just a map[string]any with extra steps
	var assertedClaims jwt.MapClaims
	assertedClaims = expectedClaims

	if diff := cmp.Diff(assertedClaims, parsedToken.Claims); diff != "" {
		t.Errorf("claims not passed back correctly\n%s\n", diff)
	}
}

func TestHandleWellKnown(t *testing.T) {
	testProvider, err := provider.NewMockAuth("es256", "sig", []string{"verify"})
	if err != nil {
		t.Fatalf("error creating mock auth provider: %s\n", err)
	}

	testServer := server{
		auth: testProvider,
	}

	testRequest := httptest.NewRequest(http.MethodPost, "/auth/.well-known/jwks.json", nil)
	testRecorder := httptest.NewRecorder()

	testServer.handleWellKnown(testRecorder, testRequest)
	if testRecorder.Code != http.StatusOK {
		t.Errorf("error handling get well-known\nresponse code: %d\nbody: %s", testRecorder.Code, testRecorder.Body)
	}

	var result provider.KeysetResponse
	decoder := json.NewDecoder(testRecorder.Body)
	err = decoder.Decode(&result)
	if err != nil {
		t.Fatalf("error unmarshalling response: %s\n", err)
	}

	expected := testProvider.GetKeyResponse()
	if diff := cmp.Diff(expected, result); diff != "" {
		t.Errorf("bad return from handle func\n%s\n", diff)
	}
}

func TestParseKeyOps(t *testing.T) {
	testOps := " foo,  bar, baz "
	expectedOps := []string{"foo", "bar", "baz"}

	result := parseKeyOps(testOps)

	if diff := cmp.Diff(result, expectedOps); diff != "" {
		t.Errorf("ops not parsed correctly\n%s\n", diff)
	}
}

func createParser(methods []string) *jwt.Parser {
	return jwt.NewParser(
		jwt.WithStrictDecoding(),
		jwt.WithValidMethods(methods),
	)
}
