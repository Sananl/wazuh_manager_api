package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// LoginRequest struct สำหรับรับข้อมูล Login (Mixed)
type LoginRequest struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	Password  string `json:"password" binding:"required"`
}

// LoginFirstNameRequest struct สำหรับรับข้อมูล Login ด้วย First Name
type LoginFirstNameRequest struct {
	FirstName string `json:"first_name" binding:"required"`
	Password  string `json:"password" binding:"required"`
}

// ฟังก์ชัน Login (Mixed: Email or FirstName)
func login(c *gin.Context) {
	var loginReq LoginRequest

	// Bind JSON request to struct
	if err := c.ShouldBindJSON(&loginReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// ตรวจสอบว่ามี Email หรือ FirstName อย่างน้อยหนึ่งอย่าง
	if loginReq.Email == "" && loginReq.FirstName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email or First Name is required"})
		return
	}

	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
		return
	}

	var user User
	// สร้าง Query พื้นฐาน เพื่อหา User ก่อน (ยังไม่ตรวจสอบรหัสผ่านในขั้นตอนนี้)
	query := db

	// เพิ่มเงื่อนไขการค้นหาตาม input ที่ส่งมา
	if loginReq.Email != "" && loginReq.FirstName != "" {
		query = query.Where("email = ? OR first_name = ?", loginReq.Email, loginReq.FirstName)
	} else if loginReq.Email != "" {
		query = query.Where("email = ?", loginReq.Email)
	} else {
		query = query.Where("first_name = ?", loginReq.FirstName)
	}

	if err := query.First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// ตรวจสอบรหัสผ่านที่ได้รับกับรหัสผ่านที่ Hash ไว้ในฐานข้อมูล
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginReq.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// ถ้าเจอ User และรหัสผ่านถูกต้อง
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"user":    user,
	})
}

// ฟังก์ชัน Login ด้วย First Name เท่านั้น
func loginByFirstName(c *gin.Context) {
	var loginReq LoginFirstNameRequest

	// Bind JSON request to struct
	if err := c.ShouldBindJSON(&loginReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "First Name and Password are required"})
		return
	}

	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
		return
	}

	var user User
	// ค้นหา user จาก first_name ก่อน
	if err := db.Where("first_name = ?", loginReq.FirstName).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// ตรวจสอบรหัสผ่านที่ได้รับกับรหัสผ่านที่ Hash ไว้ในฐานข้อมูล
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginReq.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// ถ้าเจอ User และรหัสผ่านถูกต้อง
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"user":    user,
	})
}
