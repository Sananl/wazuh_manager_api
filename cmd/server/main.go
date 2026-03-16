package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	r := InitRouter()
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}

// Handler สำหรับ Vercel (ถ้าต้องการใช้ Serverless Function)
func Handler(w http.ResponseWriter, r *http.Request) {
	router := InitRouter()
	router.ServeHTTP(w, r)
}

func InitRouter() *gin.Engine {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	r := gin.Default()
	_ = r.SetTrustedProxies(nil)

	// Route พื้นฐานสำหรับทดสอบ
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "online",
			"message": "Wazuh API Server on Vercel is running",
		})
	})

	// เรียกใช้ฟังก์ชัน login จากไฟล์ login.go
	r.POST("/login", login)
	// API สำหรับ Login ด้วย First Name เท่านั้น
	r.POST("/login/firstname", loginByFirstName)

	// API สำหรับจัดการ User (CRUD)
	r.POST("/users", createUser)       // เพิ่ม User ใหม่
	r.GET("/users", getAllUsers)       // ดึงข้อมูล User ทั้งหมด
	r.GET("/users/:id", getUserByID)   // ดึงข้อมูล User รายคน (Profile)
	r.PUT("/users/:id", updateUser)    // แก้ไขข้อมูล User ตาม ID
	r.DELETE("/users/:id", deleteUser) // ลบ User ตาม ID

	// API สำหรับ Logs
	r.GET("/logs", getAllLogs) // ดึงข้อมูล logs_data ทั้งหมด
	r.POST("/logs", createLog) // เพิ่ม Log ใหม่

	// API สำหรับ Agents
	r.GET("/agents", getAllAgents)                // ดึงข้อมูล agent ทั้งหมด
	r.POST("/agents", createAgent)                // เพิ่ม agent ใหม่
	r.GET("/agents/:id", getAgentWithLogs)        // ดึงข้อมูล agent ตาม ID พร้อม logs ทั้งหมด
	r.PUT("/agents/:id", updateAgent)             // แก้ไขข้อมูล agent ตาม ID
	r.GET("/users/:id/agents", getAgentsByUserID) // ดึงข้อมูล agents ทั้งหมดตาม user_id เจ้าของ

	// API เชื่อมต่อ Wazuh Server โดยตรง
	r.GET("/wazuh/agents", getWazuhAgentsHandler)
	r.GET("/wazuh/groups", getWazuhGroupsHandler)
	r.GET("/wazuh/groups/:name/agents", getWazuhAgentsByGroupHandler)
	r.GET("/wazuh/agents/:id", getWazuhAgentByIDHandler)
	r.POST("/wazuh/agents", createWazuhAgentHandler)       // เพิ่ม Agent
	r.DELETE("/wazuh/agents/:id", deleteWazuhAgentHandler) // ลบ Agent
	r.POST("/wazuh/agents/:id/rename", renameWazuhAgentHandler)
	r.POST("/wazuh/agents/:id/restart", restartWazuhAgentHandler)
	r.POST("/wazuh/agents/:id/stop", stopWazuhAgentBestEffortHandler)
	r.GET("/wazuh/alerts", getWazuhAlertsHandler)

	r.POST("/pin/generate", generatePIN)
	r.POST("/pin/verify", verifyPIN)
	r.GET("/pin/latest", getLatestPIN) // เพิ่ม API ดึง PIN ล่าสุดไปแสดงบนเว็บ

	r.POST("/agent-code/generate", generateAgentCode)
	r.POST("/agent-code/verify", verifyAgentCode)
	r.GET("/agent-code/latest", getLatestAgentCode)

	r.POST("/agent-commands/enqueue", enqueueAgentCommand)
	r.GET("/agent-commands/pull", pullAgentCommand)
	r.POST("/agent-commands/ack", ackAgentCommand)

	// External Control route
	r.POST("/agent/external-control", handleExternalControl)
	r.POST("/agent/external-control/", handleExternalControl)

	// r.GET("/password", generatePasswordAPI)
	return r
}
