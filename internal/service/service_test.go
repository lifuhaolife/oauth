package service

import (
	"errors"
	"testing"
)

// ===== validateUsername 测试 =====

func TestValidateUsername_Valid(t *testing.T) {
	cases := []string{
		"user",
		"user_123",
		"TestUser",
		"a1b2",
		"abcdefghij1234567890", // 20 位，最大长度
		"ALLCAPS",
		"under_score_",
	}
	for _, name := range cases {
		if err := validateUsername(name); err != nil {
			t.Errorf("用户名 %q 应合法，但返回错误: %v", name, err)
		}
	}
}

func TestValidateUsername_TooShort(t *testing.T) {
	cases := []string{"", "a", "ab", "abc"}
	for _, name := range cases {
		if err := validateUsername(name); err == nil {
			t.Errorf("用户名 %q 过短应返回错误", name)
		}
	}
}

func TestValidateUsername_TooLong(t *testing.T) {
	// 21 个字符，超过最大限制
	name := "abcdefghijklmnopqrstu"
	if err := validateUsername(name); err == nil {
		t.Errorf("用户名 %q 过长应返回错误", name)
	}
}

func TestValidateUsername_InvalidChars(t *testing.T) {
	cases := []string{
		"user name",  // 空格
		"user@name",  // @
		"user-name",  // 连字符
		"user.name",  // 点
		"用户名",        // 中文
		"user!",      // 感叹号
		"user#hash",  // #
	}
	for _, name := range cases {
		if err := validateUsername(name); err == nil {
			t.Errorf("用户名 %q 含非法字符应返回错误", name)
		}
	}
}

func TestValidateUsername_Boundary(t *testing.T) {
	// 恰好 4 位（最小合法）
	if err := validateUsername("abcd"); err != nil {
		t.Errorf("4 位用户名应合法: %v", err)
	}
	// 恰好 20 位（最大合法）
	if err := validateUsername("12345678901234567890"); err != nil {
		t.Errorf("20 位用户名应合法: %v", err)
	}
	// 3 位（非法）
	if err := validateUsername("abc"); err == nil {
		t.Error("3 位用户名应非法")
	}
	// 21 位（非法）
	if err := validateUsername("123456789012345678901"); err == nil {
		t.Error("21 位用户名应非法")
	}
}

// ===== validatePasswordStrength 测试 =====

func TestValidatePasswordStrength_Valid(t *testing.T) {
	cases := []string{
		"Admin@123",
		"Test1Pass",
		"Abcdefg1",
		"P@ssw0rd",
		"MyPass123",
		"UPPER1lower",
	}
	for _, pwd := range cases {
		if err := validatePasswordStrength(pwd); err != nil {
			t.Errorf("密码 %q 应合法，但返回错误: %v", pwd, err)
		}
	}
}

func TestValidatePasswordStrength_TooShort(t *testing.T) {
	cases := []string{"", "A1a", "Ab1", "Aa1bcde"} // 小于 8 位
	for _, pwd := range cases {
		if err := validatePasswordStrength(pwd); err == nil {
			t.Errorf("密码 %q 过短应返回错误", pwd)
		}
	}
}

func TestValidatePasswordStrength_NoUppercase(t *testing.T) {
	cases := []string{"password1", "testpass1", "abcdefg1"}
	for _, pwd := range cases {
		if err := validatePasswordStrength(pwd); err == nil {
			t.Errorf("密码 %q 无大写字母应返回错误", pwd)
		}
	}
}

func TestValidatePasswordStrength_NoLowercase(t *testing.T) {
	cases := []string{"PASSWORD1", "TESTPASS1", "ABCDEFG1"}
	for _, pwd := range cases {
		if err := validatePasswordStrength(pwd); err == nil {
			t.Errorf("密码 %q 无小写字母应返回错误", pwd)
		}
	}
}

func TestValidatePasswordStrength_NoDigit(t *testing.T) {
	cases := []string{"Password", "TestPass", "Abcdefgh"}
	for _, pwd := range cases {
		if err := validatePasswordStrength(pwd); err == nil {
			t.Errorf("密码 %q 无数字应返回错误", pwd)
		}
	}
}

func TestValidatePasswordStrength_Boundary(t *testing.T) {
	// 恰好 8 位，含大小写和数字
	if err := validatePasswordStrength("Abcdef1g"); err != nil {
		t.Errorf("8 位合法密码应通过: %v", err)
	}
	// 7 位（非法）
	if err := validatePasswordStrength("Abcd1ef"); err == nil {
		t.Error("7 位密码应非法")
	}
}

// ===== ErrUsernameAlreadyExists 哨兵错误测试 =====

func TestErrUsernameAlreadyExists_Identity(t *testing.T) {
	if !errors.Is(ErrUsernameAlreadyExists, ErrUsernameAlreadyExists) {
		t.Error("哨兵错误 errors.Is 比较失败")
	}
}

func TestErrUsernameAlreadyExists_Message(t *testing.T) {
	if ErrUsernameAlreadyExists.Error() == "" {
		t.Error("错误消息不应为空")
	}
}

func TestErrUsernameAlreadyExists_NotWrapped(t *testing.T) {
	otherErr := errors.New("other error")
	if errors.Is(otherErr, ErrUsernameAlreadyExists) {
		t.Error("不同错误不应匹配 ErrUsernameAlreadyExists")
	}
}

// ===== DB 相关测试（需要数据库时执行） =====

func TestUserAuthentication(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过数据库测试（使用 -short 标志）")
	}
	t.Skip("需要数据库连接，集成测试请在 tests/ 目录下运行")
}

func TestPasswordChange(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过数据库测试（使用 -short 标志）")
	}
	t.Skip("需要数据库连接，集成测试请在 tests/ 目录下运行")
}

func TestUserInfoRetrieval(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过数据库测试（使用 -short 标志）")
	}
	t.Skip("需要数据库连接，集成测试请在 tests/ 目录下运行")
}
