package handler

import (
	"errors"
	"net/http"

	"github/pav2345/internal/model"
	"github/pav2345/internal/service"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	Service *service.AuthService
}

func NewAuthHandler(
	service *service.AuthService,
) *AuthHandler {

	return &AuthHandler{
		Service: service,
	}
}

// Signup Handler

func (h *AuthHandler) Signup(c *gin.Context) {

	var req model.SignupRequest

	if err := c.ShouldBindJSON(&req); err != nil {

		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})

		return
	}

	response, err := h.Service.Signup(
		c.Request.Context(),
		req,
	)

	if err != nil {

		if errors.Is(err, service.ErrUserExists) {

			c.JSON(http.StatusConflict, gin.H{
				"error": err.Error(),
			})

			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Registration failed",
		})

		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Signup successful",
		"data":    response,
	})
}

// Signin Handler

func (h *AuthHandler) Signin(c *gin.Context) {

	var req model.SigninRequest

	if err := c.ShouldBindJSON(&req); err != nil {

		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})

		return
	}

	response, err := h.Service.Signin(
		c.Request.Context(),
		req,
	)

	if err != nil {

		if errors.Is(err, service.ErrInvalidCredentials) {

			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(),
			})

			return
		}

		if errors.Is(err, service.ErrInactiveUser) {

			c.JSON(http.StatusForbidden, gin.H{
				"error": err.Error(),
			})

			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Login failed",
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Signin successful",
		"data":    response,
	})
}

// Refresh Token Handler

func (h *AuthHandler) Refresh(c *gin.Context) {

	var req model.RefreshRequest

	if err := c.ShouldBindJSON(&req); err != nil {

		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Refresh token is required",
		})

		return
	}

	response, err := h.Service.Refresh(
		c.Request.Context(),
		req.RefreshToken,
	)

	if err != nil {

		if errors.Is(err, service.ErrInvalidRefreshToken) {

			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired refresh token",
			})

			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Token refresh failed",
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Token refreshed successfully",
		"data":    response,
	})
}

// Logout Handler

func (h *AuthHandler) Logout(c *gin.Context) {

	var req model.LogoutRequest

	if err := c.ShouldBindJSON(&req); err != nil {

		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Refresh token required",
		})

		return
	}

	err := h.Service.Logout(
		c.Request.Context(),
		req.RefreshToken,
	)

	if err != nil {

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Logout failed",
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logout successful",
	})
}
