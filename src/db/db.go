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

var schemaPath = "postegres_schema_v1.sql"

func Init() error {
	once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		pool, err := pgxpool.New(ctx, "postgres://user:password@172.17.0.1:5432/db")
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
