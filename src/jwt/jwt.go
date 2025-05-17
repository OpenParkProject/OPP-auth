package jwt

import (
	"OPP/auth/api"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const TOKEN_EXPIRATION_TIME = 60 * time.Minute

var PublicKeyBase64 = os.Getenv("PUBLIC_KEY")
var PrivateKeyBase64 = os.Getenv("PRIVATE_KEY")

var PrivateKey *rsa.PrivateKey
var PublicKey *rsa.PublicKey

func init() {
	fmt.Print("Loading keys...\n")

	privateKeyPEM, err := base64.StdEncoding.DecodeString(PrivateKeyBase64)
	if err == nil {
		block, _ := pem.Decode(privateKeyPEM)
		if block != nil {
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err == nil {
				var ok bool
				PrivateKey, ok = key.(*rsa.PrivateKey)
				if !ok {
					panic("parsed private key is not an RSA private key")
				}
			}
			if PrivateKey == nil || err != nil {
				fmt.Print(err.Error())
				panic("failed to parse private key")
			}
		} else {
			panic("failed to decode private key PEM")
		}
	} else {
		panic("failed to decode private key base64")
	}

	publicKeyPEM, err := base64.StdEncoding.DecodeString(PublicKeyBase64)
	if err == nil {
		block, _ := pem.Decode(publicKeyPEM)
		if block != nil {
			publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
			PublicKey = publicKeyInterface.(*rsa.PublicKey)
			if PublicKey == nil || err != nil {
				panic("failed to parse public key")
			}
		} else {
			panic("failed to decode public key PEM")
		}
	} else {
		panic("failed to decode public key base64")
	}
}

func GenerateToken(username string, role api.UserRequestRole) (string, error) {
	if PrivateKey == nil {
		return "", errors.New("private key not available")
	}

	claims := jwt.MapClaims{
		"username": username,
		"role":     role,
		"exp":      jwt.NewNumericDate(time.Now().Add(TOKEN_EXPIRATION_TIME)),
	}
	method := jwt.SigningMethodRS512
	token := jwt.NewWithClaims(method, claims)
	tokenString, err := token.SignedString(PrivateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func ValidateToken(tokenString string) (*jwt.Token, error) {
	if PublicKey == nil {
		return nil, errors.New("public key not available")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrInvalidKeyType
		}
		return PublicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, jwt.ErrTokenExpired
	}

	return token, nil
}
