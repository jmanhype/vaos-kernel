package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	_ "github.com/lib/pq"
)

// Config holds database connection parameters.
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
}

// envOrDefault returns the environment variable value or a fallback.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// DefaultConfig returns config from environment variables, falling back to
// local development defaults.
func DefaultConfig() Config {
	port := 5432
	if p := os.Getenv("VAOS_DB_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}
	return Config{
		Host:     envOrDefault("VAOS_DB_HOST", "localhost"),
		Port:     port,
		User:     envOrDefault("VAOS_DB_USER", "postgres"),
		Password: envOrDefault("VAOS_DB_PASSWORD", "vaos"),
		Database: envOrDefault("VAOS_DB_NAME", "vaos"),
	}
}

// DB wraps the sql.DB connection pool with VAOS-specific queries.
type DB struct {
	*sql.DB
}

// New opens a connection to the database and configures the connection pool.
func New(cfg Config) (*DB, error) {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Database)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(1 * time.Minute)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Printf("Connected to database: %s:%d/%s", cfg.Host, cfg.Port, cfg.Database)

	return &DB{DB: db}, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.DB.Close()
}
