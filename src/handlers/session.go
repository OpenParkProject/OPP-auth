package handlers

import (
	"OPP/auth/api"
	"OPP/auth/auth"
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

func getLoggedUser(c *gin.Context, userDao dao.UserDao) (*api.UserResponse, api.UserRequestRole, error) {
	curUsername := c.Request.Context().Value("username")
	if curUsername == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return nil, "", nil
	}
	curUsernameStr, ok := curUsername.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get username"})
		return nil, "", nil
	}
	user, err := userDao.GetUserByUsername(c.Request.Context(), curUsernameStr)
	if err != nil {
		if err == dao.ErrUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return nil, "", nil
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		return nil, "", err
	}

	curRole := c.Request.Context().Value("role")
	if curRole == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return nil, "", nil
	}
	curRoleStr, ok := curRole.(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get role"})
		return nil, "", nil
	}
	curUserRole := api.UserRequestRole(curRoleStr)
	return user, curUserRole, nil
}

func (h *SessionHandlers) GetPubKey(c *gin.Context) {
	if jwt.PublicKeyBase64 == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Public key not available"})
	} else {
		c.JSON((http.StatusAccepted), gin.H{"pubkey": jwt.PublicKeyBase64})
	}
}

func (h *SessionHandlers) Register(c *gin.Context) {
	newUser := api.UserRequest{}
	if err := c.ShouldBindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Default to creating a normal user if role is not specified
	if newUser.Role == nil {
		defaultRole := api.UserRequestRoleDriver
		newUser.Role = &defaultRole
	}

	// If registering as an admin or controller, verify permissions
	if *newUser.Role == api.UserRequestRoleAdmin || *newUser.Role == api.UserRequestRoleController {
		// Check if the current user is authenticated with admin privileges
		_, role, err := auth.AuthenticationFunc(c.GetHeader("Authorization"))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed: " + err.Error()})
			return
		}

		// Check if the user has admin privileges
		if role != api.UserRequestRoleAdmin {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin privileges required to register " + string(*newUser.Role) + " accounts"})
			return
		}
	}

	// For regular users, allow unauthenticated registration

	// Check if the user already exists
	_, err := h.dao.GetUserByUsername(c.Request.Context(), newUser.Username)
	if err != dao.ErrUserNotFound {
		c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		return
	}
	emailstr := string(newUser.Email)
	_, err = h.dao.GetUserByEmail(c.Request.Context(), emailstr)
	if err != dao.ErrUserNotFound {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already in use"})
		return
	}

	// Add the user to the database
	var id int64
	id, err = h.dao.AddUser(c.Request.Context(), newUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add user"})
		return
	}
	token, err := jwt.GenerateToken(newUser.Username, *newUser.Role)
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
			Role:     api.UserResponseRole(*newUser.Role),
			Username: newUser.Username,
			Email:    newUser.Email,
			Name:     newUser.Name,
			Surname:  newUser.Surname,
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
	user, err := h.dao.GetUserByUsername(c.Request.Context(), session.Username)
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
	user, userRole, err := getLoggedUser(c, h.dao)
	if err != nil || user == nil {
		return
	}

	// No need to fetch the user again since we already have it
	// return a new token for the authenticated user
	token, err := jwt.GenerateToken(user.Username, userRole)
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
			Role:     api.UserResponseRole(string(userRole)),
		},
	}
	c.JSON(http.StatusOK, sessionResponse)
}
