package db

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct {
	pool *pgxpool.Pool
}

// Singleton instance of DB
var instance *DB
var once sync.Once
var initErr error

var schemaPath = "postgres_schema_v1.sql"

var OPP_AUTH_DB_HOST = os.Getenv("OPP_AUTH_DB_HOST")
var OPP_AUTH_DB_PORT = os.Getenv("OPP_AUTH_DB_PORT")
var POSTGRES_AUTH_USER = os.Getenv("POSTGRES_AUTH_USER")
var POSTGRES_AUTH_PASSWORD = os.Getenv("POSTGRES_AUTH_PASSWORD")
var POSTGRES_AUTH_DB = os.Getenv("POSTGRES_AUTH_DB")

func Init() error {
	once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		pool, err := pgxpool.New(ctx, fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
			POSTGRES_AUTH_USER,
			POSTGRES_AUTH_PASSWORD,
			OPP_AUTH_DB_HOST,
			OPP_AUTH_DB_PORT,
			POSTGRES_AUTH_DB,
		))
		if err != nil {
			initErr = fmt.Errorf("unable to create connection pool: %w", err)
			return
		}
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			initErr = fmt.Errorf("database ping failed: %w", err)
			return
		}

		// Read schema file
		schemaSQL, err := os.ReadFile("db/" + schemaPath)
		if err != nil {
			pool.Close()
			initErr = fmt.Errorf("failed to read schema file: %w", err)
			return
		}
		// Apply schema
		_, err = pool.Exec(ctx, string(schemaSQL))
		if err != nil {
			pool.Close()
			initErr = fmt.Errorf("failed to apply database schema: %w", err)
			return
		}

		instance = &DB{pool: pool}
		fmt.Println("Database connection pool created successfully")
	})

	return initErr
}

func GetDB() *DB {
	return instance
}

func (d *DB) Close() {
	if d.pool != nil {
		d.pool.Close()
		d.pool = nil
	}
}

func (d *DB) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	if d.pool == nil {
		return nil, pgx.ErrTxClosed
	}
	return d.pool.Query(ctx, query, args...)
}

func (d *DB) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	if d.pool == nil {
		return nil
	}
	return d.pool.QueryRow(ctx, query, args...)
}

func (d *DB) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if d.pool == nil {
		return pgconn.CommandTag{}, pgx.ErrTxClosed
	}
	return d.pool.Exec(ctx, query, args...)
}
