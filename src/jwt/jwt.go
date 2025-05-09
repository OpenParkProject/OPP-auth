package jwt

import (
	"OPP/auth/api"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
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

func AuthenticationFunc(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
	req := input.RequestValidationInput.Request
	if req == nil {
		return errors.New("missing HTTP request in authentication input")
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		return errors.New("missing Authorization header")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return errors.New("invalid Authorization header format")
	}

	tokenstr := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := ValidateToken(tokenstr)
	if err != nil {
		return errors.New("failed to parse token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return errors.New("invalid token")
	}

	expire, err := claims.GetExpirationTime()
	if err != nil {
		return errors.New("failed to get expiration time")
	}

	if expire.Before(time.Now()) {
		return errors.New("token expired")
	}

	username, ok := claims["username"].(string)
	if !ok {
		return errors.New("missing username in token claims")
	}
	role, ok := claims["role"].(string)
	if !ok {
		return errors.New("missing role in token claims")
	}

	// Update the request context with the username and role
	ctx = context.WithValue(ctx, "username", username)
	ctx = context.WithValue(ctx, "role", role)
	*req = *req.WithContext(ctx)

	return nil
}
