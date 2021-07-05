package mock

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"strings"
	"time"
)

type Token struct {
	KeyID    string
	TeamID   string
	IssuedAt int64
}

func (t *Token) Expired() bool {
	return time.Now().Unix() > t.IssuedAt+3600
}

type header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

type payload struct {
	Issuer   string `json:"iss"`
	IssuedAt int64  `json:"iat"`
}

func DecodeToken(bearer string) (*Token, error) {
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return nil, errors.New("encoded jwt token must have three parts")
	}

	hs, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	var h header
	err = json.Unmarshal(hs, &h)
	if err != nil {
		return nil, err
	}

	if h.Algorithm != "ES256" {
		return nil, errors.New("jwt alg not ES256")
	}
	if h.KeyID == "" {
		return nil, errors.New("jwt kid empty")
	}

	ps, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var p payload
	err = json.Unmarshal(ps, &p)
	if err != nil {
		return nil, err
	}

	if p.Issuer == "" {
		return nil, errors.New("jwt iss empty")
	}

	return &Token{
		KeyID:    h.KeyID,
		TeamID:   p.Issuer,
		IssuedAt: p.IssuedAt,
	}, nil
}

func AuthKeyFromFile(filename string) (*ecdsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return AuthKeyFromBytes(bytes)
}

func AuthKeyFromBytes(bytes []byte) (*ecdsa.PrivateKey, error) {
	b, _ := pem.Decode(bytes)
	if b == nil {
		return nil, errors.New("invalid .p8 PEM")
	}

	p8, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}

	key, ok := p8.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not ECDSA private key")
	}
	return key, nil
}

func VerifyJWT(token string, pub *ecdsa.PublicKey) (bool, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, errors.New("encoded jwt token must have three parts")
	}

	hash := crypto.SHA256.New()
	_, err := hash.Write([]byte(parts[0] + "." + parts[1]))
	if err != nil {
		return false, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false, err
	}
	if len(sig) != 64 {
		return false, errors.New("invalid jwt signature size")
	}

	r := new(big.Int)
	r.SetBytes(sig[:32])

	s := new(big.Int)
	s.SetBytes(sig[32:])

	return ecdsa.Verify(pub, hash.Sum(nil), r, s), nil
}
