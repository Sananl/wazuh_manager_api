package main

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type Agent struct {
	AgentID         int    `json:"agent_id" gorm:"column:agent_id;primaryKey;autoIncrement"`
	UserID          int    `json:"user_id" gorm:"column:user_id"`
	AgentName       string `json:"agent_name" gorm:"column:agent_name"`
	OperatingSystem string `json:"operating_system" gorm:"column:operating_system"`
	Status          string `json:"status" gorm:"column:status"`
	Description     string `json:"description" gorm:"column:description"`
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
