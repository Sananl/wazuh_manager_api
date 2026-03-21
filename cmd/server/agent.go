package main

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Agent struct {
	AgentID         int    `json:"agent_id" gorm:"column:agent_id;primaryKey;autoIncrement"`
	UserID          int    `json:"user_id" gorm:"column:user_id"`
	AgentName       string `json:"agent_name" gorm:"column:agent_name"`
	OperatingSystem string `json:"operating_system" gorm:"column:operating_system"`
	Status          string `json:"status" gorm:"column:status"`
	Description     string `json:"description" gorm:"column:description"`
}

// WazuhAgent สำหรับเก็บข้อมูลจากมือถือและสั่ง Start
type WazuhAgent struct {
	AgentID       int    `json:"agent_id" gorm:"column:agent_id;primaryKey;autoIncrement"`
	UserID        int    `json:"user_id" gorm:"column:user_id"`
	AgentName     string `json:"agent_name" gorm:"column:agent_name"`
	WazuhID       string `json:"wazuh_id" gorm:"column:wazuh_id"`
	IP            string `json:"ip" gorm:"column:ip"`
	OSName        string `json:"os_name" gorm:"column:os_name"`
	OSPlatform    string `json:"os_platform" gorm:"column:os_platform"`
	OSVersion     string `json:"os_version" gorm:"column:os_version"`
	WazuhVersion  string `json:"wazuh_version" gorm:"column:wazuh_version"`
	LastKeepAlive string `json:"last_keep_alive" gorm:"column:last_keep_alive"`
	Status        string `json:"status" gorm:"column:status"`
	Description   string `json:"description" gorm:"column:description"`
}

func (Agent) TableName() string {
	return "agent"
}

func (WazuhAgent) TableName() string {
	return "wazuh_agent"
}

func getAllAgents(c *gin.Context) {
	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed: " + err.Error()})
		return
	}

	pageStr := c.DefaultQuery("page", "1")
	limitStr := c.DefaultQuery("limit", "10")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 10
	}

	offset := (page - 1) * limit

	var agents []Agent
	var total int64

	if err := db.Table("agent").Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while counting agents"})
		return
	}

	if err := db.Table("agent").Offset(offset).Limit(limit).Find(&agents).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while fetching agents"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": agents,
		"meta": gin.H{
			"total":       total,
			"page":        page,
			"limit":       limit,
			"total_pages": (total + int64(limit) - 1) / int64(limit),
		},
	})
}

func createAgent(c *gin.Context) {
	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed: " + err.Error()})
		return
	}

	var input struct {
		UserID          int    `json:"user_id"`
		AgentName       string `json:"agent_name"`
		OperatingSystem string `json:"operating_system"`
		Status          string `json:"status"`
		Description     string `json:"description"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if input.UserID == 0 || input.AgentName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id and agent_name are required"})
		return
	}

	agent := Agent{
		UserID:          input.UserID,
		AgentName:       input.AgentName,
		OperatingSystem: input.OperatingSystem,
		Status:          input.Status,
		Description:     input.Description,
	}

	if agent.Status == "" {
		agent.Status = "active"
	}

	if err := db.Table("agent").Create(&agent).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create agent"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"agent": agent})
}

func getAgentWithLogs(c *gin.Context) {
	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed: " + err.Error()})
		return
	}

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent ID"})
		return
	}

	var agent Agent
	if err := db.Table("agent").Where("agent_id = ?", id).First(&agent).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
		return
	}

	var logs []LogData
	if err := db.Table("logs_data").Where("agent_id = ?", id).Order("time DESC").Find(&logs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while fetching logs for agent"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"agent": agent,
		"logs":  logs,
	})
}

// ฟังก์ชันแก้ไขข้อมูล Agent (Update)
func updateAgent(c *gin.Context) {
	id := c.Param("id")
	var input Agent
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
		return
	}

	var agent Agent
	// ตรวจสอบว่ามี Agent นี้หรือไม่
	if err := db.Table("agent").Where("agent_id = ?", id).First(&agent).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
		return
	}

	// อัปเดตข้อมูล (ไม่ให้อัปเดต agent_id)
	if err := db.Table("agent").Model(&agent).Omit("agent_id").Updates(input).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update agent"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Agent updated successfully", "agent": agent})
}

// ฟังก์ชันดึงข้อมูล Agents ทั้งหมดของ User คนใดคนหนึ่ง (โดยใช้ user_id)
func getAgentsByUserID(c *gin.Context) {
	userID := c.Param("id")
	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
		return
	}

	var agents []Agent
	// ค้นหา Agents ทั้งหมดที่มี user_id ตรงกับที่ส่งมา
	if err := db.Table("agent").Where("user_id = ?", userID).Find(&agents).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while fetching agents for user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"agents": agents})
}

// connectAgentFromMobile รับข้อมูลจากมือถือและสั่งให้ Agent Start
func connectAgentFromMobile(c *gin.Context) {
	var input WazuhAgent
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	// ตรวจสอบข้อมูลจำเป็นที่ได้จากรูป
	if input.WazuhID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "wazuh_id (ID 009) is required"})
		return
	}

	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
		return
	}

	// ค้นหาว่ามี Agent นี้อยู่แล้วหรือไม่ (ตาม wazuh_id)
	var agent WazuhAgent
	if err := db.Table("wazuh_agent").Where("wazuh_id = ?", input.WazuhID).First(&agent).Error; err != nil {
		// ถ้าไม่เจอ ให้สร้างใหม่
		if err := db.Table("wazuh_agent").Create(&input).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create agent in database"})
			return
		}
		agent = input
	} else {
		// ถ้าเจอ ให้กดอัปเดตข้อมูลล่าสุดจากมือถือ
		if err := db.Table("wazuh_agent").Model(&agent).Updates(input).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update agent status"})
			return
		}
	}

	// สร้างคำสั่ง "start" ให้ Agent ในตาราง agent_commands
	// ฝั่ง Agent จะใช้ API GET /agent-commands/pull?agent_id=... เพื่อดึงคำสั่งนี้ไปรัน
	now := time.Now()
	cmd := AgentCommand{
		ID:        uuid.New().String(),
		UserID:    strconv.Itoa(agent.UserID),
		AgentID:   agent.WazuhID,
		Action:    "start",
		Status:    "pending",
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := db.Table("agent_commands").Create(&cmd).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enqueue start command for agent"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Agent connected and start command enqueued successfully",
		"agent":      agent,
		"command_id": cmd.ID,
	})
}
