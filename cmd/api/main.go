package main

import (
	"log"
	"net/http"
	"os"

	"github/pav2345/internal/database"
	"github/pav2345/internal/handler"
	"github/pav2345/internal/middleware"
	"github/pav2345/internal/repository"
	"github/pav2345/internal/route"
	"github/pav2345/internal/service"

	"github.com/gin-gonic/gin"
)

func main() {

	// 1. Load environment variables
	dsn := os.Getenv("DATABASE_URL")
	jwtSecret := os.Getenv("JWT_SECRET")

	if dsn == "" || len(jwtSecret) < 32 {
		log.Fatal("DATABASE_URL and a JWT_SECRET of at least 32 characters are required")
	}

	// 2. Connect PostgreSQL
	db, err := database.Connect(dsn)
	if err != nil {
		log.Fatal("Database connection failed:", err)
	}
	defer db.Close()

	// 3. Initialize Repository
	authRepo := repository.NewAuthRepository(db)

	// 4. Initialize Service
	authService := service.NewAuthService(
		authRepo,
		jwtSecret,
	)

	// 5. Initialize Handler
	authHandler := handler.NewAuthHandler(
		authService,
	)

	// 6. Initialize Gin Router
	router := gin.Default()

	// 7. Register Public Routes
	route.RegisterAuthRoutes(
		router,
		authHandler,
	)

	// 8. Register Protected Routes
	protected := router.Group("/api/v1")

	protected.Use(
		middleware.AuthMiddleware(jwtSecret),
	)

	// Temporary protected profile endpoint
	protected.GET("/profile", func(c *gin.Context) {

		userID, exists := c.Get("user_id")

		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Authenticated successfully",
			"user_id": userID,
		})
	})

	// 9. Start Server
	log.Println("Server running on :8080")

	if err := router.Run(":8080"); err != nil {
		log.Fatal("Server failed:", err)
	}
}
