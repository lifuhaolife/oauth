// Package tests provides integration tests for the auth service
package tests

import (
	"os"
	"testing"

	"auth-service/internal/config"
	"auth-service/internal/keystore"
	"auth-service/internal/model"
	"auth-service/internal/service"
)

// TestMain is the entry point for running all tests in this package
func TestMain(m *testing.M) {
	// Setup: Initialize test database and services
	if err := setupTestEnvironment(); err != nil {
		panic(err)
	}

	// Run tests
	code := m.Run()

	// Teardown: Clean up test database
	teardownTestEnvironment()

	os.Exit(code)
}

// setupTestEnvironment initializes test database and services
func setupTestEnvironment() error {
	// Set test environment variables
	os.Setenv("DB_HOST", "localhost")
	os.Setenv("DB_PORT", "3306")
	os.Setenv("DB_USER", "root")
	os.Setenv("DB_PASSWORD", "root")
	os.Setenv("DB_NAME", "auth_service_test")
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("MASTER_KEY", "dGVzdF9tYXN0ZXJfa2V5X2Zvcl90ZXN0aW5nXzEyMzQ=")

	// Load config
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}

	// Initialize database
	if err := model.InitDB(cfg); err != nil {
		// Database connection failed, skip DB-dependent tests
		// Set environment variable to indicate DB is unavailable
		os.Setenv("TEST_DB_AVAILABLE", "false")
		return nil
	}

	os.Setenv("TEST_DB_AVAILABLE", "true")

	// Initialize keystore
	if err := keystore.InitKeyStore(cfg); err != nil {
		return err
	}

	// Initialize services
	service.InitServices()

	// Clean test database
	db := model.GetDB()
	if err := db.Migrator().DropTable(&model.User{}, &model.TokenBlacklist{}, &model.LoginLog{}); err != nil {
		// Table might not exist yet, ignore error
	}

	// Run migrations
	if err := db.AutoMigrate(&model.User{}, &model.TokenBlacklist{}, &model.LoginLog{}); err != nil {
		return err
	}

	return nil
}

// teardownTestEnvironment cleans up after tests
func teardownTestEnvironment() {
	db := model.GetDB()
	if db != nil {
		// Clean up test tables
		db.Migrator().DropTable(&model.User{}, &model.TokenBlacklist{}, &model.LoginLog{})
	}
}