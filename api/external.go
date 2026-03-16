package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
)

// ExternalControlRequest รับคำสั่ง Start/Stop จาก Client
type ExternalControlRequest struct {
	AgentID string `json:"agent_id" binding:"required"`
	AgentIP string `json:"agent_ip" binding:"required"`
	Action  string `json:"action" binding:"required,oneof=start stop"` // บังคับว่าเป็น start หรือ stop เท่านั้น
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func executeExternalControl(agentID string, agentIP string, action string) (string, error) {
	agentID = strings.TrimSpace(agentID)
	agentIP = strings.TrimSpace(agentIP)
	action = strings.ToLower(strings.TrimSpace(action))

	if agentID == "" || agentIP == "" {
		return "", errors.New("agent_id and agent_ip are required")
	}
	if action != "start" && action != "stop" {
		return "", errors.New("action must be start or stop")
	}

	sshUser := strings.TrimSpace(os.Getenv("AGENT_SSH_USER"))
	sshPass := os.Getenv("AGENT_SSH_PASS")
	sshKeyPath := strings.TrimSpace(os.Getenv("AGENT_SSH_KEY_PATH"))
	sshPort := strings.TrimSpace(os.Getenv("AGENT_SSH_PORT"))
	if sshPort == "" {
		sshPort = "22"
	}

	timeoutSeconds := 10
	if v := strings.TrimSpace(os.Getenv("AGENT_SSH_TIMEOUT_SECONDS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			timeoutSeconds = n
		}
	}

	scriptPath := strings.TrimSpace(os.Getenv("AGENT_SCRIPT_PATH"))
	if scriptPath == "" {
		scriptPath = "/Desktop/Wazuh-Linux/main.py"
	}

	if sshUser == "" {
		return "", errors.New("AGENT_SSH_USER is required")
	}

	var authMethods []ssh.AuthMethod
	if sshKeyPath != "" {
		keyBytes, err := os.ReadFile(sshKeyPath)
		if err != nil {
			return "", fmt.Errorf("failed to read AGENT_SSH_KEY_PATH: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse AGENT_SSH_KEY_PATH: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if sshPass != "" {
		authMethods = append(authMethods, ssh.Password(sshPass))
	}
	if len(authMethods) == 0 {
		return "", errors.New("AGENT_SSH_PASS or AGENT_SSH_KEY_PATH is required")
	}

	sshConfig := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(timeoutSeconds) * time.Second,
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(agentIP, sshPort), sshConfig)
	if err != nil {
		return "", fmt.Errorf("failed to connect to %s: %w", agentIP, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	var actionFlag string
	if action == "start" {
		actionFlag = "--start-agent"
	} else {
		actionFlag = "--stop-agent"
	}

	command := fmt.Sprintf(
		"python3 %s %s %s %s",
		shellQuote(scriptPath),
		actionFlag,
		shellQuote(agentIP),
		shellQuote(agentID),
	)

	output, err := session.CombinedOutput(command)
	if err != nil {
		return string(output), fmt.Errorf("failed to execute command: %w", err)
	}

	return string(output), nil
}

// handleExternalControl เรียกโปรแกรมภายนอกเพื่อควบคุม Agent
// กรณี API อยู่คนละเครื่องกับ Agent ต้องใช้ SSH เพื่อสั่งงานข้ามเครื่อง
func handleExternalControl(c *gin.Context) {
	var req ExternalControlRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	output, err := executeExternalControl(req.AgentID, req.AgentIP, req.Action)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   err.Error(),
			"details": output,
		})
		return
	}

	// กรณีรันผ่าน
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Command executed successfully on %s", req.AgentIP),
		"output":  output,
	})
}
