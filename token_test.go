package mock

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestTokenExpired(t *testing.T) {
	token := &Token{
		IssuedAt: time.Now().Unix(),
	}

	if token.Expired() {
		t.Error("Token must be valid")
	}

	token.IssuedAt = time.Now().Unix() - 3601
	if !token.Expired() {
		t.Error("Token must be expired")
	}
}

func TestAuthKeyFromBytes(t *testing.T) {
	pem := `-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgodDhM6dpwS6cNtS3
nPA41Vs3vqloEKwSYAi5ILTdm3ygCgYIKoZIzj0DAQehRANCAATqkU98jtUIDH7n
dW8vbVTfCuY9zw3CFkmeMzncdymE0lPdlpAVh/Np78DNWHaAQ5gXhR27LhLE6cYr
NJ7qj9gT
-----END PRIVATE KEY-----`

	key, err := AuthKeyFromBytes([]byte(pem))
	if err != nil {
		t.Error("Error must be nil")
	}
	if key == nil {
		t.Error("Key must be not nil")
	}
}

func TestAuthKeyFromBytes_EmptyBlockBytes(t *testing.T) {
	pem := `-----BEGIN PRIVATE KEY-----
-----END PRIVATE KEY-----`

	key, err := AuthKeyFromBytes([]byte(pem))
	if err == nil {
		t.Error("Error must be not nil")
	}
	if key != nil {
		t.Error("Key must be nil")
	}
}

func TestAuthKeyFromBytes_EmptyPEM(t *testing.T) {
	key, err := AuthKeyFromBytes([]byte(""))
	if err == nil {
		t.Error("Error must be not nil")
	}
	if key != nil {
		t.Error("Key must be nil")
	}
}

func TestAuthKeyFromFile(t *testing.T) {
	_, err := AuthKeyFromFile("test/AuthKey_82M5U9676G.p8")
	if err != nil {
		t.Error(err)
	}
}

func TestAuthKeyFromFile_BadPath(t *testing.T) {
	key, err := AuthKeyFromFile("")
	if err == nil {
		t.Error("Error must be not nil")
	}
	if key != nil {
		t.Error("Key must be nil")
	}
}

func TestGenerateAuthKeyPEM(t *testing.T) {
	pemKey, err := GenerateAuthKeyPEM()
	if err != nil {
		t.Error(err)
	}

	block, _ := pem.Decode(pemKey)
	if block == nil {
		t.Error("Cannot parse PEM")
	}

	p8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Error(err)
	}

	_, ok := p8.(*ecdsa.PrivateKey)
	if !ok {
		t.Error("Not ECDSA private key")
	}
}
