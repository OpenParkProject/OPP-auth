package handlers

import (
	"OPP/auth/api"
	"OPP/auth/dao"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

type UserHandlers struct {
	dao dao.UserDao
}

func NewUserHandler() *UserHandlers {
	return &UserHandlers{
		dao: *dao.NewUserDao(),
	}
}

func (uh *UserHandlers) GetUsers(c *gin.Context, params api.GetUsersParams) {
	// Auth middleware sets values in request context
	// not in gin context
	username := c.Request.Context().Value("username")
	if username == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	_, ok := username.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get username"})
		return
	}
	role := c.Request.Context().Value("role")
	if role == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	roleStr, ok := role.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get role"})
		return
	}
	if roleStr != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	users := uh.dao.GetUsers(c.Request.Context(), params.Limit, params.Offset)
	c.JSON(http.StatusOK, users)
}

func (uh *UserHandlers) GetUser(c *gin.Context) {
	username := c.Request.Context().Value("username")
	if username == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	usernameStr, ok := username.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get username"})
		return
	}

	user, err := uh.dao.GetUser(c.Request.Context(), usernameStr)
	if err != nil {
		if errors.Is(err, dao.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user"})
		return
	}
	c.JSON(http.StatusOK, user)
}

func (uh *UserHandlers) DeleteUsers(c *gin.Context) {
	username := c.Request.Context().Value("username")
	if username == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	_, ok := username.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get username"})
		return
	}
	role := c.Request.Context().Value("role")
	if role == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	roleStr, ok := role.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get role"})
		return
	}
	if roleStr != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	if err := uh.dao.DeleteAllUsers(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete all users"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "all users deleted successfully"})
}

func (uh *UserHandlers) DeleteUser(c *gin.Context) {
	username := c.Request.Context().Value("username")
	if username == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	usernameStr, ok := username.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get username"})
		return
	}

	if err := uh.dao.DeleteUser(c.Request.Context(), usernameStr); err != nil {
		if err == dao.ErrUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "user deleted successfully"})
}

func (uh *UserHandlers) UpdateUser(c *gin.Context) {
	username := c.Request.Context().Value("username")
	if username == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	usernameStr, ok := username.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get username"})
		return
	}

	var userRequest api.UserRequest
	if err := c.ShouldBindJSON(&userRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if err := uh.dao.UpdateUser(c.Request.Context(), usernameStr, userRequest); err != nil {
		if err == dao.ErrUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		if err == dao.ErrUserAlreadyExists {
			c.JSON(http.StatusConflict, gin.H{"error": "email already in use"})
			return
		}
		if errors.Is(err, dao.ErrInvalidUser) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user data"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user updated successfully"})
}
