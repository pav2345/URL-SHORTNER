package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func AuthMiddleware(jwtSecret string) gin.HandlerFunc {

	return func(c *gin.Context) {

		// 1. Get Authorization header
		authHeader := c.GetHeader("Authorization")

		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header missing",
			})
			c.Abort()
			return
		}

		// 2. Validate Bearer token format
		parts := strings.SplitN(authHeader, " ", 2)

		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization format",
			})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// 3. Parse JWT
		claims := &jwt.RegisteredClaims{}

		token, err := jwt.ParseWithClaims(
			tokenString,
			claims,
			func(token *jwt.Token) (interface{}, error) {

				// Only allow HS256
				if token.Method != jwt.SigningMethodHS256 {
					return nil, jwt.ErrSignatureInvalid
				}

				return []byte(jwtSecret), nil
			},
			jwt.WithIssuer("url-shortener"),
			jwt.WithAudience("url-shortener-api"),
			jwt.WithExpirationRequired(),
		)

		// 4. Validate token
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		// 5. Extract user ID
		userID, err := strconv.ParseInt(claims.Subject, 10, 64)

		if err != nil || userID <= 0 {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid user identity",
			})
			c.Abort()
			return
		}

		// 6. Store user ID in Gin context
		c.Set("user_id", userID)

		// 7. Continue to next handler
		c.Next()
	}
}
