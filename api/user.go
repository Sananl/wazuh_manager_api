package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// User represents the user model in the database
type User struct {
	UserID    int    `json:"user_id" gorm:"column:user_id;primaryKey;autoIncrement"`
	Email     string `json:"email" gorm:"column:email"`
	FirstName string `json:"first_name" gorm:"column:first_name"`
	LastName  string `json:"last_name" gorm:"column:last_name"`
	Type      int    `json:"type" gorm:"column:type"`
	Image     string `json:"image" gorm:"column:image"`
	Password  string `json:"password" gorm:"column:password"`
}

// ฟังก์ชันดึงข้อมูล User ทั้งหมด (Read)
func getAllUsers(c *gin.Context) {
	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed: " + err.Error()})
		return
	}

	var users []User
	// ค้นหาข้อมูลทั้งหมดจากตาราง users
	if err := db.Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while fetching users"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

// ฟังก์ชันเพิ่ม User ใหม่ (Create)
func createUser(c *gin.Context) {
	var input User
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// ตรวจสอบข้อมูลจำเป็น
	if input.Email == "" || input.Password == "" || input.FirstName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email, Password, and First Name are required"})
		return
	}

	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
		return
	}

	// ตรวจสอบว่ามี Email นี้ในระบบหรือยัง
	var count int64
	db.Model(&User{}).Where("email = ?", input.Email).Count(&count)
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email already exists"})
		return
	}

	// บันทึกข้อมูลลงฐานข้อมูล
	if err := db.Create(&input).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User created successfully", "user": input})
}

// ฟังก์ชันแก้ไขข้อมูล User (Update)
func updateUser(c *gin.Context) {
	id := c.Param("id")
	var input User
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Log ข้อมูลที่ได้รับมาเพื่อ Debug
	fmt.Printf("Received Input for Update: %+v\n", input)

	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
		return
	}

	var user User
	// ตรวจสอบว่ามี User นี้หรือไม่
	if err := db.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// อัปเดตข้อมูล (ใช้ Updates เพื่ออัปเดตเฉพาะฟิลด์ที่ส่งมา และป้องกันการแก้ user_id)
	if err := db.Model(&user).Omit("user_id").Updates(input).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully", "user": user})
}

// ฟังก์ชันลบ User (Delete)
func deleteUser(c *gin.Context) {
	id := c.Param("id")

	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
		return
	}

	// ลบข้อมูล User ตาม ID
	if err := db.Delete(&User{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not delete user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}
