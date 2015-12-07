package hashi

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/xordataexchange/superdog"
)

func TestGetKey(t *testing.T) {
	resp := `{
	"lease_id": "secret/keys/test/1/b34fa8d3-3121-6b24-403a-e0016ec24f29",
	"lease_duration": 2592000,
	"renewable": false,
	"data": {
		"block_mode": "GCM",
		"cipher": "AES",
		"key": "REVGQVVMVCBYT1IgS0VZMQo=",
		"version": "1"
	}
}`

	handler := func(w http.ResponseWriter, req *http.Request) {
		if req.RequestURI == "/v1/secret/keys/test/1" {
			w.Write([]byte(resp))
		}
	}

	c, ln := testHTTPServer(t, http.HandlerFunc(handler))
	defer ln.Close()
	v, err := NewVault(c)
	if err != nil {
		t.Fatal("Failed to create vault.", err)
	}

	key, err := v.GetKey("test", 1)
	if err != nil {
		t.Fatal(err)
	}

	if key.Version != 1 || key.Cipher != superdog.AES || key.CipherBlockMode != superdog.GCM {
		t.Fatal("Key returned is invalid")
	}
}

func TestGetKeyVersionMismatch(t *testing.T) {
	resp := `{
	"lease_id": "secret/keys/test/1/b34fa8d3-3121-6b24-403a-e0016ec24f29",
	"lease_duration": 2592000,
	"renewable": false,
	"data": {
		"block_mode": "GCM",
		"cipher": "AES",
		"key": "REVGQVVMVCBYT1IgS0VZMgo=",
		"version": "2"
	}
}`

	handler := func(w http.ResponseWriter, req *http.Request) {
		if req.RequestURI == "/v1/secret/keys/test/1" {
			w.Write([]byte(resp))
		}
	}

	c, ln := testHTTPServer(t, http.HandlerFunc(handler))
	defer ln.Close()
	v, err := NewVault(c)
	if err != nil {
		t.Fatal("Failed to create vault.", err)
	}

	_, err = v.GetKey("test", 1)
	if err != ErrVersionMismatch {
		t.Fatal("Expected version mismatch error")
	}
}

func TestCurrentKeyVersion(t *testing.T) {
	resp := `{
	"lease_id": "secret/keys/test/current/b34fa8d3-3121-6b24-403a-e0016ec24f29",
	"lease_duration": 2592000,
	"renewable": false,
	"data": {
		"latest": "2"
	}
}`

	handler := func(w http.ResponseWriter, req *http.Request) {
		if req.RequestURI == "/v1/secret/keys/test/current" {
			w.Write([]byte(resp))
		}
	}

	c, ln := testHTTPServer(t, http.HandlerFunc(handler))
	defer ln.Close()
	v, err := NewVault(c)
	if err != nil {
		t.Fatal("Failed to create vault.", err)
	}

	version, err := v.CurrentKeyVersion("test")
	if err != nil {
		t.Fatal(err)
	}

	if version != 2 {
		t.Fatal("Expected current key version to be 2")
	}
}

func TestAuthAppIDValid(t *testing.T) {
	valid := `{"lease_id":"","renewable":false,"lease_duration":0,"data":null,"auth":{"client_token":"10e19bf2-7e1d-f9f5-f181-4a712d0754de","policies":["root"],"metadata":{"app-id":"sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3","user-id":"sha1:dc724af18fbdd4e59189f5fe768a5f8311527050"},"lease_duration":0,"renewable":false}}`
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte(valid))
	}

	c, ln := testHTTPServer(t, http.HandlerFunc(handler))
	defer ln.Close()

	v, err := NewVault(c)
	if err != nil {
		t.Fatal("Failed to create vault.", err)
	}

	err = v.AuthAppID("test", "testing")
	if err != nil {
		t.Fatal("Failed to authenticate using AppID", err)
	}

	if v.Token() != "10e19bf2-7e1d-f9f5-f181-4a712d0754de" {
		t.Fatal("Failed to authenticate using AppID, invalid token returned.")
	}
}

func TestAuthAppIDInvalid(t *testing.T) {
	invalid := `{"errors":["invalid user ID or app ID"]}`
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(invalid))
	}

	c, ln := testHTTPServer(t, http.HandlerFunc(handler))
	defer ln.Close()

	v, err := NewVault(c)
	if err != nil {
		t.Fatal("Failed to create vault.", err)
	}

	err = v.AuthAppID("test2", "testing")
	if err == nil {
		t.Fatal("Invalid login should return error")
	}
}

func TestGetSalt(t *testing.T) {
	resp := `{
	"lease_id": "secret/salts/ssn/1/b34fa8d3-3121-6b24-403a-e0016ec24f29",
	"lease_duration": 2592000,
	"renewable": false,
	"data": {
		"salt": "QUJDMTIzCg==",
		"version": "1"
	}
}`

	handler := func(w http.ResponseWriter, req *http.Request) {
		if req.RequestURI == "/v1/secret/salts/ssn/1" {
			w.Write([]byte(resp))
		}
	}

	c, ln := testHTTPServer(t, http.HandlerFunc(handler))
	defer ln.Close()
	v, err := NewVault(c)
	if err != nil {
		t.Fatal("Failed to create vault.", err)
	}

	salt, err := v.GetSalt("ssn", 1)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(salt, []byte("ABC123")) {
		t.Fatal("Salt returned does not match.")
	}
}

func TestCurrentSalts(t *testing.T) {
	resp := `{
	"lease_id": "secret/salts/ssn/current/b34fa8d3-3121-6b24-403a-e0016ec24f29",
	"lease_duration": 2592000,
	"renewable": false,
	"data": {
		"salts": "1,2,3",
		"latest": "3"
	}
}`

	handler := func(w http.ResponseWriter, req *http.Request) {
		if req.RequestURI == "/v1/secret/salts/ssn/current" {
			w.Write([]byte(resp))
		}
	}

	c, ln := testHTTPServer(t, http.HandlerFunc(handler))
	defer ln.Close()
	v, err := NewVault(c)
	if err != nil {
		t.Fatal("Failed to create vault.", err)
	}

	salts, err := v.CurrentSalts("ssn")
	if err != nil {
		t.Fatal(err)
	}

	if len(salts) != 3 {
		t.Fatal("Expected 3 salts to be returned")
	}
}

func TestCurrentSaltVersion(t *testing.T) {
	resp := `{
	"lease_id": "secret/salts/ssn/current/b34fa8d3-3121-6b24-403a-e0016ec24f29",
	"lease_duration": 2592000,
	"renewable": false,
	"data": {
		"salts": "1,2,3",
		"latest": "3"
	}
}`

	handler := func(w http.ResponseWriter, req *http.Request) {
		if req.RequestURI == "/v1/secret/salts/ssn/current" {
			w.Write([]byte(resp))
		}
	}

	c, ln := testHTTPServer(t, http.HandlerFunc(handler))
	defer ln.Close()
	v, err := NewVault(c)
	if err != nil {
		t.Fatal("Failed to create vault.", err)
	}

	version, err := v.CurrentSaltVersion("ssn")
	if err != nil {
		t.Fatal(err)
	}

	if version != 3 {
		t.Fatal("Expected current salt version to be 3")
	}
}

func testHTTPServer(
	t *testing.T, handler http.Handler) (*api.Config, net.Listener) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	server := &http.Server{Handler: handler}
	go server.Serve(ln)

	config := api.DefaultConfig()
	config.Address = fmt.Sprintf("http://%s", ln.Addr())

	return config, ln
}
