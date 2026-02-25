package service

import (
	"errors"
	"testing"
)

// ==================== Validation Helper Tests (Additional) ====================

// TestValidateUsername_EmptyString tests empty username
func TestValidateUsername_EmptyString(t *testing.T) {
	err := validateUsername("")
	if err == nil {
		t.Error("validateUsername(\"\") should return error")
	}
}

// TestValidateUsername_WithNumbers tests username with numbers
func TestValidateUsername_WithNumbers(t *testing.T) {
	err := validateUsername("user123")
	if err != nil {
		t.Errorf("validateUsername(\"user123\") should be valid: %v", err)
	}
}

// TestValidatePasswordStrength_AllUppercase tests password with all uppercase
func TestValidatePasswordStrength_AllUppercase(t *testing.T) {
	err := validatePasswordStrength("PASSWORD1")
	if err == nil {
		t.Error("validatePasswordStrength(\"PASSWORD1\") should return error (needs lowercase)")
	}
}

// TestValidatePasswordStrength_AllLowercase tests password with all lowercase
func TestValidatePasswordStrength_AllLowercase(t *testing.T) {
	err := validatePasswordStrength("password1")
	if err == nil {
		t.Error("validatePasswordStrength(\"password1\") should return error (needs uppercase)")
	}
}

// TestValidatePasswordStrength_ValidMixedCase tests valid mixed case password
func TestValidatePasswordStrength_ValidMixedCase(t *testing.T) {
	err := validatePasswordStrength("MyPassword123")
	if err != nil {
		t.Errorf("validatePasswordStrength(\"MyPassword123\") should be valid: %v", err)
	}
}

// TestValidatePasswordStrength_SpecialCharsAllowed tests password with special characters
func TestValidatePasswordStrength_SpecialCharsAllowed(t *testing.T) {
	err := validatePasswordStrength("MyPass@123!#")
	if err != nil {
		t.Errorf("validatePasswordStrength with special chars should be valid: %v", err)
	}
}

// ==================== Edge Case Tests ====================

// TestValidateUsername_MaxLength tests username at maximum length
func TestValidateUsername_MaxLength(t *testing.T) {
	// 20 characters max
	maxUsername := "12345678901234567890"
	err := validateUsername(maxUsername)
	if err != nil {
		t.Errorf("validateUsername with max length should be valid: %v", err)
	}
}

// TestValidateUsername_JustOverMax tests username just over max length
func TestValidateUsername_JustOverMax(t *testing.T) {
	// 21 characters
	overMaxUsername := "123456789012345678901"
	err := validateUsername(overMaxUsername)
	if err == nil {
		t.Error("validateUsername with 21 chars should be invalid")
	}
}

// TestValidatePasswordStrength_ExactMinLength tests password at minimum length
func TestValidatePasswordStrength_ExactMinLength(t *testing.T) {
	// Exactly 8 characters with uppercase, lowercase, and digit
	minPassword := "Abcdef1g"
	err := validatePasswordStrength(minPassword)
	if err != nil {
		t.Errorf("validatePasswordStrength with min length should be valid: %v", err)
	}
}

// ==================== Error Type Tests ====================

// TestErrUsernameAlreadyExists_Type tests error type
func TestErrUsernameAlreadyExists_Type(t *testing.T) {
	if !errors.Is(ErrUsernameAlreadyExists, ErrUsernameAlreadyExists) {
		t.Error("ErrUsernameAlreadyExists should match itself")
	}
}

// TestErrUsernameAlreadyExists_DifferentError tests error comparison
func TestErrUsernameAlreadyExists_DifferentError(t *testing.T) {
	otherErr := errors.New("some other error")
	if errors.Is(otherErr, ErrUsernameAlreadyExists) {
		t.Error("Different error should not match ErrUsernameAlreadyExists")
	}
}
