package main

import (
	"fmt"
	"os"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// เชื่อมต่อฐานข้อมูล
func connectDB() (*gorm.DB, error) {
	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASS")
	dbHost := os.Getenv("DB_HOST")
	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/wazuh?charset=utf8mb4&parseTime=True&loc=Local", dbUser, dbPass, dbHost)

	logMode := logger.Silent
	if isDebugEnabled() {
		logMode = logger.Info
	}

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logMode),
	})
	if err != nil {
		return nil, err
	}

	return db, nil
}
