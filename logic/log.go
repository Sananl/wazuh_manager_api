package logic

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

type LogData struct {
	LogID       int       `json:"log_id" gorm:"column:log_id;primaryKey;autoIncrement"`
	AgentID     int       `json:"agent_id" gorm:"column:agent_id"`
	Time        time.Time `json:"time" gorm:"column:time"`
	Description string    `json:"description" gorm:"column:description"`
}

func getAllLogs(c *gin.Context) {
	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
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

	var logs []map[string]interface{}
	var total int64

	if err := db.Table("logs_data").Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while counting logs"})
		return
	}

	if err := db.Table("logs_data").Offset(offset).Limit(limit).Find(&logs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while fetching logs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": logs,
		"meta": gin.H{
			"total":       total,
			"page":        page,
			"limit":       limit,
			"total_pages": (total + int64(limit) - 1) / int64(limit),
		},
	})
}

func createLog(c *gin.Context) {
	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed: " + err.Error()})
		return
	}

	var input struct {
		AgentID     int        `json:"agent_id"`
		Time        *time.Time `json:"time"`
		Description string     `json:"description"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if input.AgentID == 0 || input.Description == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id and description are required"})
		return
	}

	logEntry := LogData{
		AgentID:     input.AgentID,
		Description: input.Description,
	}

	if input.Time != nil {
		logEntry.Time = *input.Time
	} else {
		logEntry.Time = time.Now()
	}

	if err := db.Table("logs_data").Create(&logEntry).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create log"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"log": logEntry})
}
