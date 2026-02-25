package main

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/go-sql-driver/mysql"
	"database/sql"
)

func main() {
	// 加载环境变量
	if err := godotenv.Load(); err != nil {
		fmt.Printf("加载 .env 文件失败: %v\n", err)
		return
	}

	// 获取数据库配置
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")

	fmt.Printf("数据库配置:\n")
	fmt.Printf("  Host: %s\n", host)
	fmt.Printf("  Port: %s\n", port)
	fmt.Printf("  User: %s\n", user)
	fmt.Printf("  DB: %s\n", dbname)
	fmt.Println()

	// 构建DSN
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		user, password, host, port, dbname)

	fmt.Printf("连接字符串: %s\n", dsn)
	fmt.Println()

	// 测试连接
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		fmt.Printf("打开数据库连接失败: %v\n", err)
		return
	}
	defer db.Close()

	// 测试连接
	fmt.Println("正在测试数据库连接...")
	if err := db.Ping(); err != nil {
		fmt.Printf("数据库连接失败: %v\n", err)
		return
	}

	fmt.Println("✅ 数据库连接成功!")

	// 测试查询
	fmt.Println("\n正在测试简单查询...")
	var version string
	err = db.QueryRow("SELECT VERSION()").Scan(&version)
	if err != nil {
		fmt.Printf("查询失败: %v\n", err)
		return
	}
	fmt.Printf("MySQL 版本: %s\n", version)
}