package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	r := gin.Default()

	// เรียกใช้ฟังก์ชัน login จากไฟล์ login.go
	r.POST("/login", login)
	// API สำหรับ Login ด้วย First Name เท่านั้น
	r.POST("/login/firstname", loginByFirstName)

	// API สำหรับจัดการ User (CRUD)
	r.POST("/users", createUser)       // เพิ่ม User ใหม่
	r.GET("/users", getAllUsers)       // ดึงข้อมูล User ทั้งหมด
	r.PUT("/users/:id", updateUser)    // แก้ไขข้อมูล User ตาม ID
	r.DELETE("/users/:id", deleteUser) // ลบ User ตาม ID

	// API สำหรับ Logs
	r.GET("/logs", getAllLogs) // ดึงข้อมูล logs_data ทั้งหมด
	r.POST("/logs", createLog) // เพิ่ม Log ใหม่

	// API สำหรับ Agents
	r.GET("/agents", getAllAgents) // ดึงข้อมูล agent ทั้งหมด
	r.POST("/agents", createAgent) // เพิ่ม agent ใหม่

	// r.GET("/password", generatePasswordAPI)
	// Run Server ที่ Port 8080
	r.Run(":8080")
}
