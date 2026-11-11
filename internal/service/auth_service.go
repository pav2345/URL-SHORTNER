package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github/pav2345/internal/model"
	"github/pav2345/internal/repository"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserExists          = errors.New("user already exists")
	ErrInvalidCredentials  = errors.New("invalid email or password")
	ErrInactiveUser        = errors.New("user account is inactive")
	ErrInvalidRefreshToken = errors.New("invalid or expired refresh token")
)

type AuthService struct {
	Repo      *repository.AuthRepository
	JWTSecret []byte
}

func NewAuthService(
	repo *repository.AuthRepository,
	secret string,
) *AuthService {

	return &AuthService{
		Repo:      repo,
		JWTSecret: []byte(secret),
	}
}

const (
	accessTokenDuration  = 15 * time.Minute
	refreshTokenDuration = 30 * 24 * time.Hour
)

// Generate Access Token

func (s *AuthService) generateAccessToken(
	userID int64,
) (string, error) {

	now := time.Now()

	claims := jwt.RegisteredClaims{
		Issuer:    "url-shortener",
		Subject:   stringID(userID),
		Audience:  []string{"url-shortener-api"},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(accessTokenDuration)),
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		claims,
	)

	return token.SignedString(s.JWTSecret)
}

// Generate Cryptographically Secure Refresh Token

func generateRefreshToken() (string, error) {

	bytes := make([]byte, 32)

	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

// Hash Refresh Token

func hashToken(token string) string {

	hash := sha256.Sum256([]byte(token))

	return hex.EncodeToString(hash[:])
}

// Signup

func (s *AuthService) Signup(
	ctx context.Context,
	req model.SignupRequest,
) (*model.AuthResponse, error) {

	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	existingUser, err := s.Repo.GetUserByEmail(
		ctx,
		req.Email,
	)

	if err != nil {
		return nil, err
	}

	if existingUser != nil {
		return nil, ErrUserExists
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(req.Password),
		bcrypt.DefaultCost,
	)

	if err != nil {
		return nil, err
	}

	user := &model.User{
		Name:         req.Name,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
	}

	err = s.Repo.CreateUser(ctx, user)
	if err != nil {
		return nil, err
	}

	return s.generateAuthResponse(ctx, user)
}

// Signin

func (s *AuthService) Signin(
	ctx context.Context,
	req model.SigninRequest,
) (*model.AuthResponse, error) {

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	user, err := s.Repo.GetUserByEmail(
		ctx,
		req.Email,
	)

	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, ErrInvalidCredentials
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(user.PasswordHash),
		[]byte(req.Password),
	)

	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if user.Status != "active" {
		return nil, ErrInactiveUser
	}

	return s.generateAuthResponse(ctx, user)
}

// Generate Access + Refresh Tokens

func (s *AuthService) generateAuthResponse(
	ctx context.Context,
	user *model.User,
) (*model.AuthResponse, error) {

	accessToken, err := s.generateAccessToken(user.ID)
	if err != nil {
		return nil, err
	}

	refreshToken, err := generateRefreshToken()
	if err != nil {
		return nil, err
	}

	refreshHash := hashToken(refreshToken)

	refreshExpiry := time.Now().Add(refreshTokenDuration)

	err = s.Repo.SaveRefreshToken(
		ctx,
		user.ID,
		refreshHash,
		refreshExpiry,
	)

	if err != nil {
		return nil, err
	}

	return &model.AuthResponse{
		User:         *user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessTokenDuration.Seconds()),
	}, nil
}

// Refresh Access + Refresh Tokens

func (s *AuthService) Refresh(
	ctx context.Context,
	refreshToken string,
) (*model.AuthResponse, error) {

	if strings.TrimSpace(refreshToken) == "" {
		return nil, ErrInvalidRefreshToken
	}

	// Hash the old refresh token.
	oldTokenHash := hashToken(refreshToken)

	// Generate the new refresh token.
	newRefreshToken, err := generateRefreshToken()
	if err != nil {
		return nil, err
	}

	newTokenHash := hashToken(newRefreshToken)

	newRefreshExpiry := time.Now().Add(refreshTokenDuration)

	// Rotate the token atomically in the database.
	userID, err := s.Repo.RotateRefreshToken(
		ctx,
		oldTokenHash,
		newTokenHash,
		newRefreshExpiry,
	)

	if err != nil {

		if errors.Is(err, repository.ErrRefreshTokenNotFound) ||
			errors.Is(err, repository.ErrRefreshTokenExpired) ||
			errors.Is(err, repository.ErrRefreshTokenReuse) {

			return nil, ErrInvalidRefreshToken
		}

		return nil, err
	}

	// Generate a new access token.
	accessToken, err := s.generateAccessToken(userID)
	if err != nil {
		return nil, err
	}

	return &model.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessTokenDuration.Seconds()),
	}, nil
}

// Logout

func (s *AuthService) Logout(
	ctx context.Context,
	refreshToken string,
) error {

	if strings.TrimSpace(refreshToken) == "" {
		return ErrInvalidRefreshToken
	}

	tokenHash := hashToken(refreshToken)

	return s.Repo.RevokeRefreshToken(
		ctx,
		tokenHash,
	)
}

// Convert ID to string

func stringID(id int64) string {

	return strconv.FormatInt(id, 10)
}
