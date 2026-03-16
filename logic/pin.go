package logic

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Pin struct {
	ID          string    `gorm:"column:id;primaryKey" json:"id"`
	UserID      string    `gorm:"column:user_id;index" json:"user_id"` // เพิ่ม user_id เพื่อผูกกับ user
	Hash        string    `gorm:"column:hash" json:"-"`
	RawPIN      string    `gorm:"column:raw_pin" json:"-"` // เพิ่มฟิลด์นี้สำหรับแสดงผลบนเว็บ (ถ้าจำเป็น) แต่ปกติไม่ควรเก็บ plaintext
	ExpiresAt   time.Time `gorm:"column:expires_at" json:"expires_at"`
	CreatedAt   time.Time `gorm:"column:created_at" json:"created_at"`
	Attempts    int       `gorm:"column:attempts" json:"-"`
	MaxAttempts int       `gorm:"column:max_attempts" json:"-"`
}

type AgentCode struct {
	ID          string    `gorm:"column:id;primaryKey" json:"id"`
	UserID      string    `gorm:"column:user_id;index" json:"user_id"`
	Hash        string    `gorm:"column:hash" json:"-"`
	RawCode     string    `gorm:"column:raw_code" json:"-"`
	ExpiresAt   time.Time `gorm:"column:expires_at" json:"expires_at"`
	CreatedAt   time.Time `gorm:"column:created_at" json:"created_at"`
	Attempts    int       `gorm:"column:attempts" json:"-"`
	MaxAttempts int       `gorm:"column:max_attempts" json:"-"`
}

type AgentCommand struct {
	ID         string     `gorm:"column:id;primaryKey" json:"id"`
	UserID     string     `gorm:"column:user_id;index" json:"user_id"`
	AgentID    string     `gorm:"column:agent_id;index" json:"agent_id"`
	Action     string     `gorm:"column:action" json:"action"`
	Status     string     `gorm:"column:status;index" json:"status"`
	Output     string     `gorm:"column:output" json:"output"`
	CreatedAt  time.Time  `gorm:"column:created_at" json:"created_at"`
	UpdatedAt  time.Time  `gorm:"column:updated_at" json:"updated_at"`
	ExecutedAt *time.Time `gorm:"column:executed_at" json:"executed_at"`
}

type FlexibleString string

func (s *FlexibleString) UnmarshalJSON(b []byte) error {
	var asString string
	if err := json.Unmarshal(b, &asString); err == nil {
		*s = FlexibleString(asString)
		return nil
	}

	var asNumber json.Number
	if err := json.Unmarshal(b, &asNumber); err == nil {
		*s = FlexibleString(asNumber.String())
		return nil
	}

	return errors.New("invalid string")
}

func generateNumericPIN(n int) (string, error) {
	if n <= 0 || n > 12 {
		return "", errors.New("invalid length")
	}
	buf := make([]byte, 8)
	res := make([]byte, n)
	for i := 0; i < n; i++ {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		v := binary.LittleEndian.Uint64(buf)
		res[i] = byte('0' + (v % 10))
	}
	return string(res), nil
}

func generatePIN(c *gin.Context) {
	var req struct {
		UserID      string `json:"user_id"` // รับ user_id จาก request
		Length      int    `json:"length"`
		TTLMinutes  int    `json:"ttl_minutes"`
		MaxAttempts int    `json:"max_attempts"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		req.Length = 6
		req.TTLMinutes = 10
		req.MaxAttempts = 5
	}
	// ถ้า UserID ไม่ส่งมา ให้เป็น anonymous หรือแจ้ง error ก็ได้ ตาม requirement
	// ในที่นี้ถ้าไม่ส่งมาก็ปล่อยว่างไว้ (แต่แนะนำให้ส่งมา)
	if req.UserID == "" {
		// Log warning หรือ handle ตาม business logic
		// fmt.Println("Warning: PIN generated without UserID")
	}

	if req.Length == 0 {
		req.Length = 6
	}
	if req.TTLMinutes == 0 {
		req.TTLMinutes = 10
	}
	if req.MaxAttempts == 0 {
		req.MaxAttempts = 5
	}

	pin, err := generateNumericPIN(req.Length)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pin), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash pin"})
		return
	}

	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
		return
	}
	_ = db.AutoMigrate(&Pin{})

	id := uuid.New().String()
	rec := Pin{
		ID:          id,
		UserID:      req.UserID, // บันทึก UserID
		Hash:        string(hash),
		RawPIN:      pin,
		ExpiresAt:   time.Now().Add(time.Duration(req.TTLMinutes) * time.Minute),
		CreatedAt:   time.Now(),
		Attempts:    0,
		MaxAttempts: req.MaxAttempts,
	}
	if err := db.Table("pins").Create(&rec).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store pin"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "pin": pin, "expires_at": rec.ExpiresAt})
}

// getLatestPIN ดึง PIN ล่าสุดที่ยังไม่หมดอายุ
func getLatestPIN(c *gin.Context) {
	// รับ user_id จาก query string (เช่น ?user_id=1)
	userID := c.Query("user_id")

	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
		return
	}

	// AutoMigrate ให้แน่ใจว่าตาราง pins มี structure ล่าสุด (รวม user_id)
	if err := db.AutoMigrate(&Pin{}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database migration failed"})
		return
	}

	var rec Pin
	query := db.Table("pins").Where("expires_at > ?", time.Now())

	// ถ้ามี userID ให้กรองเฉพาะของ user นั้น
	if userID != "" {
		query = query.Where("user_id = ?", userID)
	}

	// ดึง PIN ล่าสุด โดยเรียงจาก created_at desc และต้องยังไม่หมดอายุ
	if err := query.Order("created_at desc").First(&rec).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.Status(http.StatusNoContent)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch latest PIN"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":         rec.ID,
		"user_id":    rec.UserID,
		"pin":        rec.RawPIN,
		"expires_at": rec.ExpiresAt,
		"created_at": rec.CreatedAt,
	})
}

func generateAgentCode(c *gin.Context) {
	var req struct {
		UserID      string `json:"user_id"`
		Length      int    `json:"length"`
		TTLMinutes  int    `json:"ttl_minutes"`
		MaxAttempts int    `json:"max_attempts"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		req.Length = 6
		req.TTLMinutes = 10
		req.MaxAttempts = 5
	}
	if req.Length == 0 {
		req.Length = 6
	}
	if req.TTLMinutes == 0 {
		req.TTLMinutes = 10
	}
	if req.MaxAttempts == 0 {
		req.MaxAttempts = 5
	}

	code, err := generateNumericPIN(req.Length)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash code"})
		return
	}

	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
		return
	}
	if err := db.AutoMigrate(&AgentCode{}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database migration failed"})
		return
	}

	id := uuid.New().String()
	rec := AgentCode{
		ID:          id,
		UserID:      req.UserID,
		Hash:        string(hash),
		RawCode:     code,
		ExpiresAt:   time.Now().Add(time.Duration(req.TTLMinutes) * time.Minute),
		CreatedAt:   time.Now(),
		Attempts:    0,
		MaxAttempts: req.MaxAttempts,
	}
	if err := db.Table("agent_codes").Create(&rec).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store code"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "code": code, "expires_at": rec.ExpiresAt})
}

func getLatestAgentCode(c *gin.Context) {
	userID := c.Query("user_id")

	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
		return
	}
	if err := db.AutoMigrate(&AgentCode{}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database migration failed"})
		return
	}

	var rec AgentCode
	query := db.Table("agent_codes").Where("expires_at > ?", time.Now())
	if userID != "" {
		query = query.Where("user_id = ?", userID)
	}
	if err := query.Order("created_at desc").First(&rec).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.Status(http.StatusNoContent)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch latest code"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":         rec.ID,
		"user_id":    rec.UserID,
		"code":       rec.RawCode,
		"expires_at": rec.ExpiresAt,
		"created_at": rec.CreatedAt,
	})
}

func verifyAgentCode(c *gin.Context) {
	var req struct {
		ID     FlexibleString `json:"id"`
		CodeID FlexibleString `json:"code_id"`
		Code   FlexibleString `json:"code"`
		UserID FlexibleString `json:"user_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"valid": false, "error": "invalid request"})
		return
	}
	id := strings.TrimSpace(string(req.ID))
	if id == "" {
		id = strings.TrimSpace(string(req.CodeID))
	}

	code := strings.TrimSpace(string(req.Code))
	userID := strings.TrimSpace(string(req.UserID))
	if (id == "" && userID == "") || code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"valid": false, "error": "invalid request"})
		return
	}

	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"valid": false, "error": "Database connection failed"})
		return
	}
	var rec AgentCode
	if id != "" {
		if err := db.Table("agent_codes").Where("id = ?", id).First(&rec).Error; err != nil {
			c.JSON(http.StatusOK, gin.H{"valid": false})
			return
		}
	} else {
		if err := db.Table("agent_codes").
			Where("user_id = ? AND expires_at > ?", userID, time.Now()).
			Order("created_at desc").
			First(&rec).Error; err != nil {
			c.JSON(http.StatusOK, gin.H{"valid": false})
			return
		}
	}
	if time.Now().After(rec.ExpiresAt) {
		_ = db.Table("agent_codes").Where("id = ?", id).Delete(&AgentCode{}).Error
		c.JSON(http.StatusOK, gin.H{"valid": false})
		return
	}
	if rec.Attempts >= rec.MaxAttempts {
		_ = db.Table("agent_codes").Where("id = ?", id).Delete(&AgentCode{}).Error
		c.JSON(http.StatusOK, gin.H{"valid": false})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(rec.Hash), []byte(code)); err != nil {
		rec.Attempts++
		_ = db.Table("agent_codes").Where("id = ?", id).Updates(map[string]interface{}{"attempts": rec.Attempts}).Error
		c.JSON(http.StatusOK, gin.H{"valid": false})
		return
	}
	_ = db.Table("agent_codes").Where("id = ?", id).Delete(&AgentCode{}).Error
	c.JSON(http.StatusOK, gin.H{"valid": true})
}

func enqueueAgentCommand(c *gin.Context) {
	var req struct {
		UserID  string `json:"user_id"`
		AgentID string `json:"agent_id"`
		AgentIP string `json:"agent_ip"`
		Action  string `json:"action"`
		Command string `json:"command"`
		Custom  *bool  `json:"custom"`
		CodeID  string `json:"code_id"`
		Code    string `json:"code"`
		Polling bool   `json:"polling"` // เพิ่มฟิลด์ polling
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	req.UserID = strings.TrimSpace(req.UserID)
	req.AgentID = strings.TrimSpace(req.AgentID)
	req.AgentIP = strings.TrimSpace(req.AgentIP)
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	req.Command = strings.TrimSpace(req.Command)
	req.CodeID = strings.TrimSpace(req.CodeID)
	req.Code = strings.TrimSpace(req.Code)

	if req.UserID == "" || req.AgentID == "" || req.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id, agent_id, action are required"})
		return
	}
	if req.Action != "start" && req.Action != "stop" && req.Action != "restart" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action must be start, stop or restart"})
		return
	}
	// ถ้าไม่ใช่ Polling และเป็น Action "start" ให้เปลี่ยนเป็น "restart" สำหรับ Wazuh API
	if !req.Polling && req.Action == "start" {
		req.Action = "restart"
	}

	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
		return
	}
	if err := db.AutoMigrate(&AgentCommand{}, &AgentCode{}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database migration failed"})
		return
	}

	if req.CodeID != "" || req.Code != "" {
		if req.CodeID == "" || req.Code == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "code_id and code are required together"})
			return
		}

		var codeRec AgentCode
		if err := db.Table("agent_codes").Where("id = ?", req.CodeID).First(&codeRec).Error; err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid code"})
			return
		}
		if time.Now().After(codeRec.ExpiresAt) || codeRec.Attempts >= codeRec.MaxAttempts {
			_ = db.Table("agent_codes").Where("id = ?", req.CodeID).Delete(&AgentCode{}).Error
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid code"})
			return
		}
		if codeRec.UserID != "" && codeRec.UserID != req.UserID {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid code"})
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(codeRec.Hash), []byte(req.Code)); err != nil {
			codeRec.Attempts++
			_ = db.Table("agent_codes").Where("id = ?", req.CodeID).Updates(map[string]interface{}{"attempts": codeRec.Attempts}).Error
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid code"})
			return
		}
		_ = db.Table("agent_codes").Where("id = ?", req.CodeID).Delete(&AgentCode{}).Error
	}

	id := uuid.New().String()
	now := time.Now()
	cmd := AgentCommand{
		ID:        id,
		UserID:    req.UserID,
		AgentID:   req.AgentID,
		Action:    req.Action,
		Status:    "pending",
		Output:    "",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := db.Table("agent_commands").Create(&cmd).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store command"})
		return
	}

	// ถ้าเป็นการ Polling ให้หยุดแค่การเก็บลง DB แล้วส่งกลับ
	if req.Polling {
		c.JSON(http.StatusOK, gin.H{
			"command_id":   id,
			"status":       cmd.Status,
			"executed":     false,
			"executed_via": "polling_queue",
		})
		return
	}

	status := cmd.Status
	executed := false
	executedVia := ""
	outputForClient := ""
	var wazuhResponseForClient interface{} = nil

	{
		executed = true
		executedVia = "wazuh"
		now2 := time.Now()
		_ = db.Table("agent_commands").Where("id = ? AND status = ?", id, "pending").Updates(map[string]interface{}{
			"status":     "processing",
			"updated_at": now2,
		}).Error

		var output string
		var err error
		finalStatus := "done"
		custom := false
		if req.Custom != nil {
			custom = *req.Custom
		} else if req.Action == "stop" {
			custom = true
		} else if req.Action == "restart" {
			if req.Command == "" || strings.EqualFold(req.Command, "restart-wazuh") {
				custom = false
			} else {
				custom = true
			}
		} else {
			custom = true
		}

		if req.Action == "stop" {
			_, body, e := executeWazuhStopAgentBestEffort(req.AgentID, req.Command, custom)
			output = string(body)
			err = e
			var parsed interface{}
			if json.Unmarshal(body, &parsed) == nil {
				wazuhResponseForClient = parsed
			}
		} else {
			_, body, e := executeWazuhRestartAgentBestEffort(req.AgentID, req.Command, custom)
			output = string(body)
			err = e
			var parsed interface{}
			if json.Unmarshal(body, &parsed) == nil {
				wazuhResponseForClient = parsed
			}
		}

		if err != nil {
			finalStatus = "failed"
			if output == "" {
				output = err.Error()
			} else {
				output = output + "\n" + err.Error()
			}
		}

		const maxOutput = 4000
		if len(output) > maxOutput {
			output = output[:maxOutput]
		}

		now3 := time.Now()
		_ = db.Table("agent_commands").Where("id = ?", id).Updates(map[string]interface{}{
			"status":      finalStatus,
			"output":      output,
			"updated_at":  now3,
			"executed_at": now3,
		}).Error
		status = finalStatus
		outputForClient = output
	}

	c.JSON(http.StatusOK, gin.H{"command_id": id, "status": status, "executed": executed, "executed_via": executedVia, "output": outputForClient, "wazuh_response": wazuhResponseForClient})
}

func pullAgentCommand(c *gin.Context) {
	agentID := strings.TrimSpace(c.Query("agent_id"))
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id is required"})
		return
	}

	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
		return
	}
	if err := db.AutoMigrate(&AgentCommand{}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database migration failed"})
		return
	}

	var out AgentCommand
	err = db.Transaction(func(tx *gorm.DB) error {
		var rec AgentCommand
		if err := tx.Table("agent_commands").
			Where("agent_id = ? AND status = ?", agentID, "pending").
			Order("created_at asc").
			First(&rec).Error; err != nil {
			return err
		}

		now := time.Now()
		res := tx.Table("agent_commands").
			Where("id = ? AND status = ?", rec.ID, "pending").
			Updates(map[string]interface{}{"status": "processing", "updated_at": now})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		rec.Status = "processing"
		rec.UpdatedAt = now
		out = rec
		return nil
	})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.Status(http.StatusNoContent)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to pull command"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"command_id": out.ID,
		"agent_id":   out.AgentID,
		"action":     out.Action,
		"status":     out.Status,
		"created_at": out.CreatedAt,
	})
}

func ackAgentCommand(c *gin.Context) {
	var req struct {
		CommandID string `json:"command_id"`
		Status    string `json:"status"`
		Output    string `json:"output"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req.CommandID = strings.TrimSpace(req.CommandID)
	req.Status = strings.ToLower(strings.TrimSpace(req.Status))

	if req.CommandID == "" || req.Status == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "command_id and status are required"})
		return
	}
	if req.Status != "done" && req.Status != "failed" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status must be done or failed"})
		return
	}

	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection failed"})
		return
	}
	if err := db.AutoMigrate(&AgentCommand{}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database migration failed"})
		return
	}

	now := time.Now()
	res := db.Table("agent_commands").Where("id = ?", req.CommandID).Updates(map[string]interface{}{
		"status":      req.Status,
		"output":      req.Output,
		"updated_at":  now,
		"executed_at": now,
	})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update command"})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "command not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func verifyPIN(c *gin.Context) {
	var req struct {
		ID     FlexibleString `json:"id"`
		PIN    FlexibleString `json:"pin"`
		UserID FlexibleString `json:"user_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"valid": false, "error": "invalid request"})
		return
	}
	id := strings.TrimSpace(string(req.ID))
	pin := strings.TrimSpace(string(req.PIN))
	userID := strings.TrimSpace(string(req.UserID))
	if (id == "" && userID == "") || pin == "" {
		c.JSON(http.StatusBadRequest, gin.H{"valid": false, "error": "invalid request"})
		return
	}

	db, err := connectDB()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"valid": false, "error": "Database connection failed"})
		return
	}

	var rec Pin
	if id != "" {
		if err := db.Table("pins").Where("id = ?", id).First(&rec).Error; err != nil {
			c.JSON(http.StatusOK, gin.H{"valid": false})
			return
		}
	} else {
		if err := db.Table("pins").
			Where("user_id = ? AND expires_at > ?", userID, time.Now()).
			Order("created_at desc").
			First(&rec).Error; err != nil {
			c.JSON(http.StatusOK, gin.H{"valid": false})
			return
		}
	}
	if time.Now().After(rec.ExpiresAt) {
		_ = db.Table("pins").Where("id = ?", rec.ID).Delete(&Pin{}).Error
		c.JSON(http.StatusOK, gin.H{"valid": false})
		return
	}
	if rec.Attempts >= rec.MaxAttempts {
		_ = db.Table("pins").Where("id = ?", rec.ID).Delete(&Pin{}).Error
		c.JSON(http.StatusOK, gin.H{"valid": false})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(rec.Hash), []byte(pin)); err != nil {
		rec.Attempts++
		_ = db.Table("pins").Where("id = ?", rec.ID).Updates(map[string]interface{}{"attempts": rec.Attempts}).Error
		c.JSON(http.StatusOK, gin.H{"valid": false})
		return
	}
	_ = db.Table("pins").Where("id = ?", rec.ID).Delete(&Pin{}).Error
	c.JSON(http.StatusOK, gin.H{"valid": true})
}
