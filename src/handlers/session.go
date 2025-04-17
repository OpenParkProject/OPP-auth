package handlers

import (
	"github.com/gin-gonic/gin"
)

type SessionHandlers struct{}

func NewSessionHandler() *SessionHandlers {
	return &SessionHandlers{}
}

func (h *SessionHandlers) Login(c *gin.Context)             {}
func (h *SessionHandlers) Logout(c *gin.Context)            {}
func (h *SessionHandlers) GetCurrentSession(c *gin.Context) {}
