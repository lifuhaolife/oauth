package main

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	godotenv.Load()
	
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		user, password, host, port, dbname)
	
	fmt.Println("DSN:", dsn)
	fmt.Println()
	
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		fmt.Println("Open error:", err)
		return
	}
	defer db.Close()
	
	err = db.Ping()
	if err != nil {
		fmt.Println("Ping error:", err)
		return
	}
	
	fmt.Println("连接成功!")
}
