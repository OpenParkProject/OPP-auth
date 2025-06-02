package handlers

import (
	"OPP/auth/api"
	"OPP/auth/dao"
	"OPP/auth/jwt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type SessionHandlers struct {
	dao dao.UserDao
}

func NewSessionHandler() *SessionHandlers {
	return &SessionHandlers{
		dao: *dao.NewUserDao(),
	}
}

func (h *SessionHandlers) GetPubKey(c *gin.Context) {
	if jwt.PublicKeyBase64 == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Public key not available"})
	} else {
		c.JSON((http.StatusAccepted), gin.H{"pubkey": jwt.PublicKeyBase64})
	}
}

func (h *SessionHandlers) Register(c *gin.Context) {
	user := api.UserRequest{}
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if *user.Role == api.UserRequestRoleAdmin || *user.Role == api.UserRequestRoleController {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot register as" + *user.Role + ", permission denied"})
	}
	// Check if the user already exists
	_, err := h.dao.GetUser(c.Request.Context(), user.Username)
	if err != dao.ErrUserNotFound {
		c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		return
	}
	// Add the user to the database
	var id int64
	id, err = h.dao.AddUser(c.Request.Context(), user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add user"})
		return
	}
	token, err := jwt.GenerateToken(user.Username, *user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := api.SessionResponse{
		AccessToken: token,
		ExpiresIn:   int(jwt.TOKEN_EXPIRATION_TIME.Seconds()),
		TokenType:   "Bearer",
		User: api.UserResponse{
			Id:       id,
			Role:     api.UserResponseRole(*user.Role),
			Username: user.Username,
			Email:    user.Email,
			Name:     user.Name,
			Surname:  user.Surname,
		},
	}
	c.JSON(http.StatusCreated, response)
}

func (h *SessionHandlers) Login(c *gin.Context) {
	session := api.SessionRequest{}
	if err := c.ShouldBindJSON(&session); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	// Check if the user exists
	user, err := h.dao.GetUser(c.Request.Context(), session.Username)
	if err == dao.ErrUserNotFound {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check user existence"})
		return
	}
	role, err := h.dao.GetUserRole(c.Request.Context(), user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user role"})
		return
	}
	// Check if the password is correct
	if err := h.dao.CheckPassword(c.Request.Context(), session.Username, session.Password); err != nil {
		if err == dao.ErrInvalidPassword {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check password"})
		return
	}
	// Generate a new token
	token, err := jwt.GenerateToken(user.Username, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}
	sessionResponse := api.SessionResponse{
		AccessToken: token,
		ExpiresIn:   int(jwt.TOKEN_EXPIRATION_TIME.Seconds()),
		TokenType:   "Bearer",
		User: api.UserResponse{
			Id:       user.Id,
			Username: user.Username,
			Email:    user.Email,
			Name:     user.Name,
			Surname:  user.Surname,
			Role:     api.UserResponseRole(role),
		},
	}
	c.JSON(http.StatusOK, sessionResponse)
}

func (h *SessionHandlers) GetSession(c *gin.Context) {
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
	user, err := h.dao.GetUser(c.Request.Context(), usernameStr)
	if err != nil {
		if err == dao.ErrUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
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
	userRole := api.UserRequestRole(roleStr)

	// return a new token for the authenticated user
	token, err := jwt.GenerateToken(usernameStr, userRole)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}
	sessionResponse := api.SessionResponse{
		AccessToken: token,
		ExpiresIn:   int(jwt.TOKEN_EXPIRATION_TIME.Seconds()),
		TokenType:   "Bearer",
		User: api.UserResponse{
			Id:       user.Id,
			Username: user.Username,
			Email:    user.Email,
			Name:     user.Name,
			Surname:  user.Surname,
			Role:     api.UserResponseRole(roleStr),
		},
	}
	c.JSON(http.StatusOK, sessionResponse)
}
