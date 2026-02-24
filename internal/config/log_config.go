package config

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// LogLevel 日志级别
type LogLevel int

const (
	DebugLevel LogLevel = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

// LogConfig 日志配置
type LogConfig struct {
	Level      LogLevel
	File       string
	MaxSize    int // MB
	MaxBackups int
	MaxAge     int // days
	Compress   bool
}

// GlobalLogConfig 全局日志配置
var GlobalLogConfig = &LogConfig{
	Level:      InfoLevel,
	File:       "logs/app.log",
	MaxSize:    100,
	MaxBackups: 7,
	MaxAge:     30,
	Compress:   true,
}

// SetLogLevel 设置日志级别
func SetLogLevel(level string) {
	switch level {
	case "debug":
		GlobalLogConfig.Level = DebugLevel
	case "info":
		GlobalLogConfig.Level = InfoLevel
	case "warn":
		GlobalLogConfig.Level = WarnLevel
	case "error":
		GlobalLogConfig.Level = ErrorLevel
	default:
		GlobalLogConfig.Level = InfoLevel
	}
}

// IsDebugEnabled 是否启用Debug级别日志
func IsDebugEnabled() bool {
	return GlobalLogConfig.Level <= DebugLevel
}

// IsInfoEnabled 是否启用Info级别日志
func IsInfoEnabled() bool {
	return GlobalLogConfig.Level <= InfoLevel
}

// IsWarnEnabled 是否启用Warn级别日志
func IsWarnEnabled() bool {
	return GlobalLogConfig.Level <= WarnLevel
}

// SetupLogger 设置日志输出（接入 lumberjack 实现真实轮转）
func SetupLogger() {
	// 创建日志目录
	logDir := "logs"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Printf("创建日志目录失败: %v", err)
	}

	// 按日期命名日志文件
	todayFile := fmt.Sprintf("logs/app-%s.log", time.Now().Format("2006-01-02"))

	// 使用 lumberjack 实现轮转
	rotator := &lumberjack.Logger{
		Filename:   todayFile,
		MaxSize:    GlobalLogConfig.MaxSize,
		MaxBackups: GlobalLogConfig.MaxBackups,
		MaxAge:     GlobalLogConfig.MaxAge,
		Compress:   GlobalLogConfig.Compress,
	}

	// 同时输出到 stdout 和日志文件
	log.SetOutput(io.MultiWriter(os.Stdout, rotator))
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("Logger initialized: file=%s level=%v", todayFile, GlobalLogConfig.Level)
}
