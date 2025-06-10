package auth

import (
	"OPP/auth/api"
	"OPP/auth/dao"
	opp_jwt "OPP/auth/jwt"
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/golang-jwt/jwt/v5"
)

var DEBUG_MODE = os.Getenv("DEBUG_MODE")

func AuthenticationWrapperFunc(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
	req := input.RequestValidationInput.Request
	if req == nil {
		return errors.New("missing HTTP request in authentication input")
	}

	username, role, err := AuthenticationFunc(req.Header.Get("Authorization"))
	if err != nil {
		return err
	}

	// Update the request context with the username and role
	ctx = context.WithValue(ctx, "username", username)
	ctx = context.WithValue(ctx, "role", role)

	*req = *req.WithContext(ctx)

	return nil
}

// AuthenticationFunc can be used for endpoints that aren't marked as requiring authentication
// but still need to check auth tokens when provided.
// Returns (username, role, error) where error is nil if authentication succeeded
func AuthenticationFunc(authHeader string) (string, string, error) {
	// Debug mode: override username and role
	if DEBUG_MODE == "true" {
		// make sure to create a debug user if it doesn't exist
		role := api.UserRequestRoleAdmin
		debug_user := api.UserRequest{
			Username: "admin_debug",
			Password: "admin_debug",
			Role:     &role,
			Email:    "admin.debug@debug.com",
			Name:     "Admin",
			Surname:  "Debug",
		}
		_, err := dao.NewUserDao().AddUser(context.Background(), debug_user)
		if err != nil && !errors.Is(err, dao.ErrUserAlreadyExists) {
			return "", "", errors.New("failed to create debug user: " + err.Error())
		}
		return "admin_debug", "admin", nil
	}

	if authHeader == "" {
		return "", "", errors.New("missing Authorization header")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", "", errors.New("invalid Authorization header format")
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := opp_jwt.ValidateToken(tokenStr)
	if err != nil {
		return "", "", errors.New("failed to parse token: " + err.Error())
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", "", errors.New("invalid token")
	}

	// Validate expiration time
	expire, err := claims.GetExpirationTime()
	if err != nil {
		return "", "", errors.New("failed to get expiration time")
	}

	if expire.Before(time.Now()) {
		return "", "", errors.New("token expired")
	}

	username, ok := claims["username"].(string)
	if !ok {
		return "", "", errors.New("missing username in token claims")
	}

	roleStr, ok := claims["role"].(string)
	if !ok {
		return "", "", errors.New("missing role in token claims")
	}

	return username, roleStr, nil
}
