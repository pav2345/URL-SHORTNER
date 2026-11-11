package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github/pav2345/internal/model"
)

var (
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenExpired  = errors.New("refresh token expired")
	ErrRefreshTokenReuse    = errors.New("refresh token reuse detected")
)

type AuthRepository struct {
	DB *sql.DB
}

func NewAuthRepository(db *sql.DB) *AuthRepository {
	return &AuthRepository{
		DB: db,
	}
}

func (r *AuthRepository) CreateUser(
	ctx context.Context,
	user *model.User,
) error {

	query := `
		INSERT INTO users (name, email, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id, status, created_at
	`

	return r.DB.QueryRowContext(
		ctx,
		query,
		user.Name,
		user.Email,
		user.PasswordHash,
	).Scan(
		&user.ID,
		&user.Status,
		&user.CreatedAt,
	)
}

func (r *AuthRepository) GetUserByEmail(
	ctx context.Context,
	email string,
) (*model.User, error) {

	user := &model.User{}

	query := `
		SELECT id, name, email, password_hash, status, created_at
		FROM users
		WHERE email = $1
	`

	err := r.DB.QueryRowContext(
		ctx,
		query,
		email,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.PasswordHash,
		&user.Status,
		&user.CreatedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *AuthRepository) SaveRefreshToken(
	ctx context.Context,
	userID int64,
	tokenHash string,
	expiresAt time.Time,
) error {

	query := `
		INSERT INTO refresh_tokens
		(user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`

	_, err := r.DB.ExecContext(
		ctx,
		query,
		userID,
		tokenHash,
		expiresAt,
	)

	return err
}

func (r *AuthRepository) RevokeRefreshToken(
	ctx context.Context,
	tokenHash string,
) error {

	query := `
		UPDATE refresh_tokens
		SET revoked_at = CURRENT_TIMESTAMP
		WHERE token_hash = $1
		  AND revoked_at IS NULL
	`

	_, err := r.DB.ExecContext(
		ctx,
		query,
		tokenHash,
	)

	return err
}

// RotateRefreshToken atomically revokes the old refresh token
// and saves the newly generated refresh token.
func (r *AuthRepository) RotateRefreshToken(
	ctx context.Context,
	oldTokenHash string,
	newTokenHash string,
	newExpiresAt time.Time,
) (int64, error) {

	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}

	defer tx.Rollback()

	var userID int64
	var expiresAt time.Time
	var revokedAt sql.NullTime

	// Lock the existing token row.
	query := `
		SELECT user_id, expires_at, revoked_at
		FROM refresh_tokens
		WHERE token_hash = $1
		FOR UPDATE
	`

	err = tx.QueryRowContext(
		ctx,
		query,
		oldTokenHash,
	).Scan(
		&userID,
		&expiresAt,
		&revokedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrRefreshTokenNotFound
	}

	if err != nil {
		return 0, err
	}

	// Detect reuse of a previously revoked token.
	if revokedAt.Valid {

		_, err = tx.ExecContext(
			ctx,
			`
			UPDATE refresh_tokens
			SET revoked_at = CURRENT_TIMESTAMP
			WHERE user_id = $1
			  AND revoked_at IS NULL
			`,
			userID,
		)

		if err != nil {
			return 0, err
		}

		if err := tx.Commit(); err != nil {
			return 0, err
		}

		return 0, ErrRefreshTokenReuse
	}

	// Reject expired tokens.
	if !expiresAt.After(time.Now()) {

		_, err = tx.ExecContext(
			ctx,
			`
			UPDATE refresh_tokens
			SET revoked_at = CURRENT_TIMESTAMP
			WHERE token_hash = $1
			  AND revoked_at IS NULL
			`,
			oldTokenHash,
		)

		if err != nil {
			return 0, err
		}

		if err := tx.Commit(); err != nil {
			return 0, err
		}

		return 0, ErrRefreshTokenExpired
	}

	// Revoke the old token.
	_, err = tx.ExecContext(
		ctx,
		`
		UPDATE refresh_tokens
		SET revoked_at = CURRENT_TIMESTAMP
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		`,
		oldTokenHash,
	)

	if err != nil {
		return 0, err
	}

	// Store the new refresh token hash.
	_, err = tx.ExecContext(
		ctx,
		`
		INSERT INTO refresh_tokens
		(user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
		`,
		userID,
		newTokenHash,
		newExpiresAt,
	)

	if err != nil {
		return 0, err
	}

	// Commit both operations together.
	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return userID, nil
}
