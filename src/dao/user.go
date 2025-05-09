package dao

import (
	"OPP/auth/api"
	"OPP/auth/db"
	"context"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrInvalidUser       = errors.New("invalid user data")
	ErrUserNotFound      = errors.New("user not found")
	ErrInvalidPassword   = errors.New("invalid password")
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
	query := "SELECT username, name, surname, email FROM users LIMIT $1 OFFSET $2"
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
		if err := rows.Scan(&user.Username, &user.Name, &user.Surname, &user.Email); err != nil {
			fmt.Printf("row scan error: %v\n", err.Error())
			continue
		}
		users = append(users, user)
	}
	return users
}

func (d *UserDao) AddUser(c context.Context, user api.UserRequest) error {
	query := "INSERT INTO users (username, name, surname, email, password, role) VALUES ($1, $2, $3, $4, $5, $6)"
	_, err := d.db.Exec(c, query, user.Username, user.Name, user.Surname, user.Email, user.Password, user.Role)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrUserAlreadyExists
		}
		return fmt.Errorf("failed to add user: %w", err)
	}
	return nil
}

func (d *UserDao) GetUser(c context.Context, username string) (*api.UserResponse, error) {
	query := "SELECT username, name, surname, email FROM users WHERE username = $1"
	rows, err := d.db.Query(c, query, username)
	if err != nil {
		return nil, fmt.Errorf("db error: %w", err)
	}
	defer rows.Close()

	var user api.UserResponse
	if rows.Next() {
		if err := rows.Scan(&user.Username, &user.Name, &user.Surname, &user.Email); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
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

func (d *UserDao) UpdateUser(c context.Context, username string, user api.UserRequest) error {
	query := "UPDATE users SET name = $1, surname = $2, email = $3 WHERE username = $4"
	result, err := d.db.Exec(c, query, user.Name, user.Surname, user.Email, username)
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
