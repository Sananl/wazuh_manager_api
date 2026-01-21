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
