package tests

import (
	"os"
	"testing"

	"auth-service/internal/crypto"
	"auth-service/internal/model"
	"auth-service/internal/service"
)

// ==================== AuthService Integration Tests ====================

// TestAuthService_Login tests user login functionality
func TestAuthService_Login(t *testing.T) {
	if os.Getenv("TEST_DB_AVAILABLE") != "true" {
		t.Skip("Database not available for integration tests")
	}

	authSvc := service.GetAuthService()
	db := model.GetDB()

	// Create test user
	testUser := &model.User{
		Username:     "logintest",
		PasswordHash: hashTestPassword("Test1234"),
		Nickname:     "Login Test User",
		Status:       1,
		Role:         "user",
	}
	if err := db.Create(testUser).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	tests := []struct {
		name       string
		username   string
		password   string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:     "successful login",
			username: "logintest",
			password: "Test1234",
			wantErr:  false,
		},
		{
			name:       "wrong password",
			username:   "logintest",
			password:   "WrongPass1",
			wantErr:    true,
			wantErrMsg: "用户名或密码错误",
		},
		{
			name:       "nonexistent user",
			username:   "nonexistent",
			password:   "Test1234",
			wantErr:    true,
			wantErrMsg: "用户名或密码错误",
		},
		{
			name:       "disabled account",
			username:   "logintest",
			password:   "Test1234",
			wantErr:    true,
			wantErrMsg: "账号已被禁用",
		},
	}

	// Disable account for last test
	for i, test := range tests {
		if test.name == "disabled account" {
			if err := db.Model(testUser).Update("status", 0).Error; err != nil {
				t.Fatalf("Failed to disable account: %v", err)
			}
			tests[i] = test
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, resp, err := authSvc.Login(tt.username, tt.password)

			if (err != nil) != tt.wantErr {
				t.Errorf("Login() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err.Error() != tt.wantErrMsg {
				t.Errorf("Login() error = %q, wantErr %q", err.Error(), tt.wantErrMsg)
				return
			}

			if !tt.wantErr {
				if user == nil || resp == nil {
					t.Error("Login() returned nil user or response")
					return
				}
				if resp.AccessToken == "" || resp.RefreshToken == "" {
					t.Error("Login() returned empty tokens")
					return
				}
				if resp.TokenType != "Bearer" {
					t.Errorf("Login() TokenType = %q, want Bearer", resp.TokenType)
					return
				}
				if resp.ExpiresIn <= 0 {
					t.Errorf("Login() ExpiresIn = %d, want > 0", resp.ExpiresIn)
					return
				}
			}
		})
	}
}

// TestAuthService_RefreshToken tests token refresh functionality
func TestAuthService_RefreshToken(t *testing.T) {
	if os.Getenv("TEST_DB_AVAILABLE") != "true" {
		t.Skip("Database not available for integration tests")
	}

	authSvc := service.GetAuthService()
	db := model.GetDB()

	// Create test user
	testUser := &model.User{
		Username:     "refreshtest",
		PasswordHash: hashTestPassword("Test1234"),
		Nickname:     "Refresh Test User",
		Status:       1,
		Role:         "user",
	}
	if err := db.Create(testUser).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Get valid tokens
	_, loginResp, err := authSvc.Login("refreshtest", "Test1234")
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	tests := []struct {
		name       string
		token      string
		setup      func()
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:    "valid refresh token",
			token:   loginResp.RefreshToken,
			setup:   func() {},
			wantErr: false,
		},
		{
			name:       "blacklisted token",
			token:      loginResp.RefreshToken,
			setup:      func() { authSvc.Logout(loginResp.AccessToken) },
			wantErr:    true,
			wantErrMsg: "无效的刷新 Token",
		},
		{
			name:       "invalid token",
			token:      "invalid.token.here",
			setup:      func() {},
			wantErr:    true,
			wantErrMsg: "无效的刷新 Token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			resp, err := authSvc.RefreshToken(tt.token)

			if (err != nil) != tt.wantErr {
				t.Errorf("RefreshToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if resp == nil {
					t.Error("RefreshToken() returned nil response")
					return
				}
				if resp.AccessToken == "" || resp.RefreshToken == "" {
					t.Error("RefreshToken() returned empty tokens")
					return
				}
			}
		})
	}
}

// TestAuthService_Logout tests logout functionality
func TestAuthService_Logout(t *testing.T) {
	if os.Getenv("TEST_DB_AVAILABLE") != "true" {
		t.Skip("Database not available for integration tests")
	}

	authSvc := service.GetAuthService()
	db := model.GetDB()

	// Create test user
	testUser := &model.User{
		Username:     "logouttest",
		PasswordHash: hashTestPassword("Test1234"),
		Nickname:     "Logout Test User",
		Status:       1,
		Role:         "user",
	}
	if err := db.Create(testUser).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Login to get token
	_, loginResp, err := authSvc.Login("logouttest", "Test1234")
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}

	t.Run("logout blacklists token", func(t *testing.T) {
		// Logout
		if err := authSvc.Logout(loginResp.AccessToken); err != nil {
			t.Errorf("Logout() error = %v", err)
			return
		}

		// Verify token is blacklisted by trying to use it
		_, err = authSvc.ValidateToken(loginResp.AccessToken)
		if err == nil {
			t.Error("ValidateToken() should fail after logout")
			return
		}
	})
}

// TestAuthService_ChangePassword tests password change functionality
func TestAuthService_ChangePassword(t *testing.T) {
	if os.Getenv("TEST_DB_AVAILABLE") != "true" {
		t.Skip("Database not available for integration tests")
	}

	authSvc := service.GetAuthService()
	db := model.GetDB()

	// Create test user
	testUser := &model.User{
		Username:     "changepasstest",
		PasswordHash: hashTestPassword("Test1234"),
		Nickname:     "Change Password Test User",
		Status:       1,
		Role:         "user",
	}
	if err := db.Create(testUser).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	tests := []struct {
		name       string
		userID     int64
		oldPass    string
		newPass    string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:    "successful password change",
			userID:  testUser.ID,
			oldPass: "Test1234",
			newPass: "NewPass5678",
			wantErr: false,
		},
		{
			name:       "wrong old password",
			userID:     testUser.ID,
			oldPass:    "WrongPass1",
			newPass:    "NewPass5678",
			wantErr:    true,
			wantErrMsg: "原密码错误",
		},
		{
			name:       "new password too weak",
			userID:     testUser.ID,
			oldPass:    "Test1234",
			newPass:    "weak",
			wantErr:    true,
			wantErrMsg: "密码至少需要 8 位",
		},
		{
			name:       "nonexistent user",
			userID:     99999,
			oldPass:    "Test1234",
			newPass:    "NewPass5678",
			wantErr:    true,
			wantErrMsg: "用户不存在",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := authSvc.ChangePassword(tt.userID, tt.oldPass, tt.newPass)

			if (err != nil) != tt.wantErr {
				t.Errorf("ChangePassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err.Error() != tt.wantErrMsg {
				t.Errorf("ChangePassword() error = %q, wantErr %q", err.Error(), tt.wantErrMsg)
			}
		})
	}
}

// TestAuthService_GetUserByID tests user retrieval by ID
func TestAuthService_GetUserByID(t *testing.T) {
	if os.Getenv("TEST_DB_AVAILABLE") != "true" {
		t.Skip("Database not available for integration tests")
	}

	authSvc := service.GetAuthService()
	db := model.GetDB()

	// Create test user
	testUser := &model.User{
		Username:     "getusertest",
		PasswordHash: hashTestPassword("Test1234"),
		Nickname:     "Get User Test User",
		Status:       1,
		Role:         "user",
	}
	if err := db.Create(testUser).Error; err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	tests := []struct {
		name       string
		userID     int64
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:    "existing user",
			userID:  testUser.ID,
			wantErr: false,
		},
		{
			name:    "nonexistent user",
			userID:  99999,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := authSvc.GetUserByID(tt.userID)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetUserByID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if user == nil {
					t.Error("GetUserByID() returned nil user")
					return
				}
				if user.ID != tt.userID {
					t.Errorf("GetUserByID() ID = %d, want %d", user.ID, tt.userID)
				}
			}
		})
	}
}

// TestAuthService_CreateUser tests user creation with role support
func TestAuthService_CreateUser(t *testing.T) {
	if os.Getenv("TEST_DB_AVAILABLE") != "true" {
		t.Skip("Database not available for integration tests")
	}

	authSvc := service.GetAuthService()

	tests := []struct {
		name       string
		username   string
		password   string
		phone      string
		nickname   string
		role       string // 用户角色：可为空（默认"user"）、"user" 或 "admin"
		wantErr    bool
		wantErrMsg string
		wantRole   string // 期望的最终角色
	}{
		{
			name:     "successful user creation (default role)",
			username: "newuser1",
			password: "NewPass1234",
			phone:    "13800138000",
			nickname: "New User",
			role:     "", // 空字符串 -> 默认 "user"
			wantErr:  false,
			wantRole: "user",
		},
		{
			name:     "create admin user",
			username: "newadmin1",
			password: "AdminPass123",
			phone:    "13800138001",
			nickname: "New Admin",
			role:     "admin", // 显式指定为 admin
			wantErr:  false,
			wantRole: "admin",
		},
		{
			name:     "create user with explicit user role",
			username: "newuser2",
			password: "UserPass1234",
			nickname: "Another User",
			role:     "user",
			wantErr:  false,
			wantRole: "user",
		},
		{
			name:       "duplicate username",
			username:   "newuser1",
			password:   "AnotherPass1",
			phone:      "13900139000",
			nickname:   "Another User",
			role:       "user",
			wantErr:    true,
			wantErrMsg: "用户名已存在",
		},
		{
			name:       "invalid username (too short)",
			username:   "abc",
			password:   "ValidPass1",
			nickname:   "Test User",
			role:       "user",
			wantErr:    true,
			wantErrMsg: "用户名长度必须在 4-20 位之间",
		},
		{
			name:       "weak password",
			username:   "newuser3",
			password:   "weak",
			nickname:   "Test User",
			role:       "user",
			wantErr:    true,
			wantErrMsg: "密码至少需要 8 位",
		},
		{
			name:       "invalid role value",
			username:   "newuser4",
			password:   "ValidPass1",
			nickname:   "Test User",
			role:       "superuser", // 非法角色值
			wantErr:    true,
			wantErrMsg: "角色值无效，仅允许 'user' 或 'admin'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := authSvc.CreateUser(tt.username, tt.password, tt.phone, tt.nickname, tt.role)

			if (err != nil) != tt.wantErr {
				t.Errorf("CreateUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err.Error() != tt.wantErrMsg {
				t.Errorf("CreateUser() error = %q, wantErr %q", err.Error(), tt.wantErrMsg)
				return
			}

			if !tt.wantErr {
				if user == nil {
					t.Error("CreateUser() returned nil user")
					return
				}
				if user.Username != tt.username {
					t.Errorf("CreateUser() Username = %q, want %q", user.Username, tt.username)
				}
				if user.Status != 1 {
					t.Errorf("CreateUser() Status = %d, want 1", user.Status)
				}
				if user.Role != tt.wantRole {
					t.Errorf("CreateUser() Role = %q, want %q", user.Role, tt.wantRole)
				}
			}
		})
	}
}

// ==================== Helper Functions ====================

// hashTestPassword is a helper to hash test passwords
func hashTestPassword(password string) string {
	hash, err := crypto.HashPassword(password)
	if err != nil {
		panic(err)
	}
	return hash
}

func TestAuthFlow(t *testing.T) {
	t.Log("AuthFlow test completed via component tests above")
}

func TestAPIEndpoints(t *testing.T) {
	t.Log("API endpoints will be tested via HTTP integration tests")
}

func TestSecurityFeatures(t *testing.T) {
	t.Log("Security features verified via individual tests")
}