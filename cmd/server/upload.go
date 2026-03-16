package main

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// UploadImageRequest สำหรับรับข้อมูลรูปภาพแบบ Base64
type UploadImageRequest struct {
	UserID    string `json:"user_id" binding:"required"`
	ImageData string `json:"image_data" binding:"required"` // ข้อความ Base64 ของรูปภาพ
}

// uploadUserImageHandler สำหรับรับรูปภาพและบันทึกลงในฐานข้อมูลฟิลด์ image
func uploadUserImageHandler(c *gin.Context) {
	var req UploadImageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body. user_id and image_data are required."})
		return
	}

	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
		return
	}

	// แปลง user_id เป็น int
	userID, err := strconv.Atoi(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user_id format"})
		return
	}

	// ตรวจสอบว่ามี User นี้จริงไหม
	var user User
	if err := db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("User ID %d not found", userID)})
		return
	}

	// บันทึกข้อมูล Base64 ลงในฟิลด์ Image ของฐานข้อมูล
	if err := db.Model(&user).Update("image", req.ImageData).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user image in database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Image uploaded and saved to database successfully",
		"user_id": userID,
	})
}
