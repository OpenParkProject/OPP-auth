package dao

import (
	"OPP/auth/api"
	"OPP/auth/db"
	"OPP/auth/otp"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrInvalidUser       = errors.New("invalid user data")
	ErrUserNotFound      = errors.New("user not found")
	ErrInvalidPassword   = errors.New("invalid password")
	ErrOTPNotFound       = errors.New("OTP not found")
)

type UserDao struct {
	db db.DB
}

func NewUserDao() *UserDao {
	return &UserDao{
		db: *db.GetDB(),
	}
}

func (d *UserDao) GetUsers(c context.Context, limit *int, offset *int) []api.UserResponse {
	query := "SELECT user_id, username, name, surname, email, role FROM users LIMIT $1 OFFSET $2"
	params := []any{20, 0}
	if limit != nil {
		params[0] = *limit
	}
	if offset != nil {
		params[1] = *offset
	}

	var users []api.UserResponse
	rows, err := d.db.Query(c, query, params...)
	if err != nil {
		fmt.Printf("db error: %v\n", err.Error())
		return users
	}
	defer rows.Close()

	for rows.Next() {
		var user api.UserResponse
		var roleStr string
		if err := rows.Scan(&user.Id, &user.Username, &user.Name, &user.Surname, &user.Email, &roleStr); err != nil {
			fmt.Printf("row scan error: %v\n", err.Error())
			continue
		}
		user.Role = api.UserResponseRole(roleStr)
		users = append(users, user)
	}
	return users
}

func (d *UserDao) AddUser(c context.Context, user api.UserRequest) (int64, error) {
	query := "INSERT INTO users (username, name, surname, email, password, role) VALUES ($1, $2, $3, $4, $5, $6) RETURNING user_id"
	row := d.db.QueryRow(c, query, user.Username, user.Name, user.Surname, user.Email, user.Password, user.Role)

	var id int64
	err := row.Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return 0, ErrUserAlreadyExists
		}
		return 0, fmt.Errorf("failed to add user: %w", err)
	}
	return id, nil
}

func (d *UserDao) GetUserByUsername(c context.Context, username string) (*api.UserResponse, error) {
	query := "SELECT user_id, username, name, surname, email, role FROM users WHERE username = $1"
	rows, err := d.db.Query(c, query, username)
	if err != nil {
		return nil, fmt.Errorf("db error: %w", err)
	}
	defer rows.Close()

	var user api.UserResponse
	var roleStr string
	if rows.Next() {
		if err := rows.Scan(&user.Id, &user.Username, &user.Name, &user.Surname, &user.Email, &roleStr); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		user.Role = api.UserResponseRole(roleStr)
		return &user, nil
	}
	return nil, ErrUserNotFound
}

func (d *UserDao) GetUserByEmail(c context.Context, email string) (*api.UserResponse, error) {
	query := "SELECT user_id, username, name, surname, email, role FROM users WHERE email = $1"
	rows, err := d.db.Query(c, query, email)
	if err != nil {
		return nil, fmt.Errorf("db error: %w", err)
	}
	defer rows.Close()
	var user api.UserResponse
	var roleStr string
	if rows.Next() {
		if err := rows.Scan(&user.Id, &user.Username, &user.Name, &user.Surname, &user.Email, &roleStr); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		user.Role = api.UserResponseRole(roleStr)
		return &user, nil
	}
	return nil, ErrUserNotFound
}

func (d *UserDao) GetUserRole(c context.Context, username string) (api.UserRequestRole, error) {
	query := "SELECT role FROM users WHERE username = $1"
	rows, err := d.db.Query(c, query, username)
	if err != nil {
		return "", fmt.Errorf("db error: %w", err)
	}
	defer rows.Close()

	var role api.UserRequestRole
	if rows.Next() {
		if err := rows.Scan(&role); err != nil {
			return "", fmt.Errorf("failed to scan user role: %w", err)
		}
		return role, nil
	}
	return "", ErrUserNotFound
}

func (d *UserDao) CheckPassword(c context.Context, username string, password string) error {
	query := "SELECT password FROM users WHERE username = $1"
	rows, err := d.db.Query(c, query, username)
	if err != nil {
		return fmt.Errorf("db error: %w", err)
	}
	defer rows.Close()

	var storedPassword string
	if rows.Next() {
		if err := rows.Scan(&storedPassword); err != nil {
			return fmt.Errorf("failed to scan password: %w", err)
		}
		if storedPassword != password {
			return ErrInvalidPassword
		}
		return nil
	}
	return ErrUserNotFound
}

func (d *UserDao) DeleteAllUsers(c context.Context) error {
	query := "DELETE FROM users"
	_, err := d.db.Exec(c, query)
	if err != nil {
		return fmt.Errorf("failed to delete all users: %w", err)
	}
	return nil
}

func (d *UserDao) DeleteUser(c context.Context, username string) error {
	query := "DELETE FROM users WHERE username = $1"
	result, err := d.db.Exec(c, query, username)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (d *UserDao) UpdateUser(c context.Context, username string, user api.UpdateUserRequest) error {
	query := "UPDATE users SET name = $1, surname = $2, email = $3, password = $4 WHERE username = $5"
	result, err := d.db.Exec(c, query, user.Name, user.Surname, user.Email, user.Password, username)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrUserAlreadyExists
		}
		return fmt.Errorf("failed to update user: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (d *UserDao) UpdateUserByUsername(c context.Context, username string, user api.UserRequest) error {
	query := "UPDATE users SET username = $1, name = $2, surname = $3, email = $4 WHERE username = $5"
	result, err := d.db.Exec(c, query, user.Username, user.Name, user.Surname, user.Email, username)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrUserAlreadyExists
		}
		return fmt.Errorf("failed to update user by username: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (d *UserDao) DeleteUserByUsername(c context.Context, username string) error {
	query := "DELETE FROM users WHERE username = $1"
	result, err := d.db.Exec(c, query, username)
	if err != nil {
		return fmt.Errorf("failed to delete user by username: %w", err)
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (d *UserDao) GenerateOTP(c context.Context, username string) (api.OTPResponse, error) {
	user, err := d.GetUserByUsername(c, username)
	if err != nil {
		return api.OTPResponse{}, fmt.Errorf("failed to get user: %w", err)
	}

	// Create OTP
	otpCode, exp_date, err := otp.GenerateOTP()
	if err != nil {
		return api.OTPResponse{}, fmt.Errorf("failed to generate OTP: %w", err)
	}
	query := "INSERT INTO otps (user_id, otp_code, expires_at) VALUES ($1, $2, $3) RETURNING otp_id"
	row := d.db.QueryRow(c, query, user.Id, otpCode, exp_date)
	var otpId int64
	err = row.Scan(&otpId)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return api.OTPResponse{}, ErrUserAlreadyExists
		}
		return api.OTPResponse{}, fmt.Errorf("failed to insert OTP: %w", err)
	}
	return api.OTPResponse{
		Otp:        otpCode,
		ValidUntil: exp_date,
	}, nil
}

func (d *UserDao) ValidateOTP(c context.Context, otpCode string) (bool, error) {
	// Check for currently valid OTP
	query := `
        SELECT otp_id, user_id, expires_at FROM otps 
        WHERE otp_code = $1 AND expires_at > CURRENT_TIMESTAMP
        ORDER BY created_at DESC LIMIT 1
    `
	var otpID int64
	var userID int64
	var expiresAt time.Time

	row := d.db.QueryRow(c, query, otpCode)
	if err := row.Scan(&otpID, &userID, &expiresAt); err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			return false, nil
		}
		return false, fmt.Errorf("failed to validate OTP: %w", err)
	}

	return true, nil
}

func (d *UserDao) GetUserByOTP(c context.Context, otpCode string) (*api.UserResponse, error) {
	query := `
        SELECT u.user_id, u.username, u.email, u.name, u.surname, u.role
        FROM users u
        JOIN otps o ON u.user_id = o.user_id
        WHERE o.otp_code = $1 AND o.expires_at > CURRENT_TIMESTAMP
    `
	row := d.db.QueryRow(c, query, otpCode)

	var user api.UserResponse
	if err := row.Scan(&user.Id, &user.Username, &user.Email, &user.Name, &user.Surname, &user.Role); err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by OTP: %w", err)
	}
	return &user, nil
}
