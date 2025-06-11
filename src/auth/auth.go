package auth

import (
	"OPP/auth/api"
	"OPP/auth/dao"
	opp_jwt "OPP/auth/jwt"
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var DEBUG_MODE = os.Getenv("DEBUG_MODE")

var (
	ErrUnauthorized    = errors.New("unauthorized")
	ErrFailedToGetUser = errors.New("failed to get user from context")
	ErrFailedToGetRole = errors.New("failed to get role from context")
)

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
		role := api.UserRequestRoleSuperuser
		debug_user := api.UserRequest{
			Username: "superuser_debug",
			Password: "superuser_debug",
			Role:     &role,
			Email:    "superuser.debug@debug.com",
			Name:     "superuser",
			Surname:  "debug",
		}
		// Check if the user already exists
		existingUser, err := dao.NewUserDao().GetUserByUsername(context.Background(), debug_user.Username)
		if err != nil && !errors.Is(err, dao.ErrUserNotFound) {
			return "", "", errors.New("failed to check debug user existence: " + err.Error())
		}
		if existingUser == nil {
			_, err := dao.NewUserDao().AddUser(context.Background(), debug_user)
			if err != nil && !errors.Is(err, dao.ErrUserAlreadyExists) {
				return "", "", errors.New("failed to create debug user: " + err.Error())
			}
		}
		return "superuser_debug", "superuser", nil
	}

	if authHeader == "" {
		return "", "", errors.New("missing Authorization header")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", "", errors.New("invalid Authorization header format")
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := opp_jwt.ValidateAccessToken(tokenStr)
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

func GetPermissions(c *gin.Context) (string, string, error) {
	// Auth middleware sets values in request context
	// not in gin context
	username := c.Request.Context().Value("username")
	if username == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": ErrUnauthorized.Error()})
		return "", "", ErrUnauthorized
	}
	usernameStr, ok := username.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": ErrFailedToGetUser.Error()})
		return "", "", ErrFailedToGetUser
	}
	role := c.Request.Context().Value("role")
	if role == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": ErrUnauthorized.Error()})
		return "", "", ErrUnauthorized
	}
	roleStr, ok := role.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": ErrFailedToGetRole.Error()})
		return "", "", ErrFailedToGetRole
	}

	return usernameStr, roleStr, nil
}
