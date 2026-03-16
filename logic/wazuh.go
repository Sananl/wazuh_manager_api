package logic

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func isDebugEnabled() bool {
	level := strings.ToLower(strings.TrimSpace(os.Getenv("LOG_LEVEL")))
	if level == "debug" {
		return true
	}

	v := strings.ToLower(strings.TrimSpace(os.Getenv("DEBUG")))
	return v == "1" || v == "true" || v == "yes"
}

func debugf(format string, args ...interface{}) {
	if !isDebugEnabled() {
		return
	}
	fmt.Printf(format, args...)
}

func debugBody(label string, body []byte) {
	if !isDebugEnabled() {
		return
	}

	const max = 1000
	preview := body
	if len(preview) > max {
		preview = preview[:max]
	}
	fmt.Printf("DEBUG: %s (len=%d): %s\n", label, len(body), string(preview))
}

// WazuhConfig เก็บค่า Configuration สำหรับเชื่อมต่อ Wazuh API
type WazuhConfig struct {
	URL      string
	User     string
	Password string
	Token    string
}

// WazuhAuthResponse โครงสร้าง Response ของ Token
type WazuhAuthResponse struct {
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
}

// WazuhAgentResponse โครงสร้าง Response ของ Agent list จาก Wazuh
type WazuhAgentResponse struct {
	Data struct {
		AffectedItems []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
			Name   string `json:"name"`
			IP     string `json:"ip"`
			OS     struct {
				Name     string `json:"name"`
				Platform string `json:"platform"`
				Version  string `json:"version"`
			} `json:"os"`
			Version       string `json:"version"`
			Description   string `json:"description"`
			LastKeepAlive string `json:"lastKeepAlive"`
		} `json:"affected_items"`
		TotalAffectedItems int `json:"total_affected_items"`
	} `json:"data"`
}

// WazuhAlertsResponse โครงสร้าง Response ของ Alerts (Security Events)
type WazuhAlertsResponse struct {
	Data struct {
		AffectedItems []struct {
			Timestamp string `json:"timestamp"`
			Rule      struct {
				ID          string `json:"id"`
				Level       int    `json:"level"`
				Description string `json:"description"`
			} `json:"rule"`
			Agent struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				IP          string `json:"ip"`
				Description string `json:"description"`
			} `json:"agent"`
			Manager struct {
				Name string `json:"name"`
			} `json:"manager"`
			ID      string `json:"id"`
			Cluster struct {
				Name string `json:"name"`
			} `json:"cluster"`
			Decoder struct {
				Name string `json:"name"`
			} `json:"decoder"`
			Location string `json:"location"`
		} `json:"affected_items"`
		TotalAffectedItems int `json:"total_affected_items"`
	} `json:"data"`
}

type WazuhIndexerConfig struct {
	URL      string
	User     string
	Password string
}

type WazuhIndexerSearchResponse struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []struct {
			Source map[string]interface{} `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// getWazuhConfig อ่านค่าจาก Environment Variable
func getWazuhConfig() WazuhConfig {
	return WazuhConfig{
		URL:      os.Getenv("WAZUH_API_URL"),
		User:     os.Getenv("WAZUH_USER"),
		Password: os.Getenv("WAZUH_PASS"),
		Token:    os.Getenv("WAZUH_TOKEN"),
	}
}

func getWazuhIndexerConfig() WazuhIndexerConfig {
	return WazuhIndexerConfig{
		URL:      os.Getenv("WAZUH_INDEXER_URL"),
		User:     os.Getenv("WAZUH_INDEXER_USER"),
		Password: os.Getenv("WAZUH_INDEXER_PASS"),
	}
}

func fetchIndexerAlerts(agentID string, limit int, selectFields string, groupName string) ([]map[string]interface{}, int, error) {
	cfg := getWazuhIndexerConfig()
	if cfg.URL == "" || cfg.User == "" || cfg.Password == "" {
		return nil, 0, fmt.Errorf("Wazuh indexer configuration missing in .env")
	}

	if limit <= 0 {
		limit = 10000
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	searchURL := fmt.Sprintf("%s/wazuh-alerts-*/_search", cfg.URL)

	body := make(map[string]interface{})
	body["size"] = limit
	body["sort"] = []map[string]interface{}{
		{
			"@timestamp": map[string]string{
				"order": "desc",
			},
		},
	}

	// เลือกเฉพาะฟิลด์ที่ต้องการเพื่อลดขนาดข้อมูล
	if selectFields != "" {
		body["_source"] = selectFields
	}

	// สร้างเงื่อนไขการกรอง (Filter)
	var filters []map[string]interface{}

	if agentID != "" {
		filters = append(filters, map[string]interface{}{
			"term": map[string]interface{}{
				"agent.id": agentID,
			},
		})
	}

	if groupName != "" {
		filters = append(filters, map[string]interface{}{
			"term": map[string]interface{}{
				"agent.group": groupName,
			},
		})
	}

	if len(filters) > 0 {
		body["query"] = map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": filters,
			},
		}
	}

	reqBody, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequest("POST", searchURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, 0, err
	}

	req.SetBasicAuth(cfg.User, cfg.Password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("indexer returned status %s: %s", resp.Status, string(respBody))
	}

	debugBody("Indexer Response", respBody)

	var searchResp WazuhIndexerSearchResponse
	if err := json.Unmarshal(respBody, &searchResp); err != nil {
		return nil, 0, err
	}

	alerts := make([]map[string]interface{}, 0, len(searchResp.Hits.Hits))
	for _, h := range searchResp.Hits.Hits {
		alerts = append(alerts, h.Source)
	}

	return alerts, searchResp.Hits.Total.Value, nil
}

// AuthError สำหรับส่งสถานะ error กลับไปยัง Client ให้เหมาะกับสถานะจริงของ Wazuh
type AuthError struct {
	StatusCode int
	Message    string
}

func (e *AuthError) Error() string {
	return e.Message
}

// getWazuhToken ขอ Token จาก Wazuh API
func getWazuhToken(config WazuhConfig) (string, error) {
	// ถ้ามี Token อยู่แล้วใน ENV ให้ใช้ทันที
	if config.Token != "" {
		return config.Token, nil
	}

	// ลอง Path ปกติก่อน
	token, err := tryAuth(config, config.URL+"/security/user/authenticate")
	if err == nil {
		return token, nil
	}
	debugf("DEBUG: Failed to auth at %s: %v\n", config.URL+"/security/user/authenticate", err)

	// ถ้าไม่ผ่าน ลอง Path /api (สำหรับผ่าน Proxy/Nginx)
	token, err = tryAuth(config, config.URL+"/api/security/user/authenticate")
	if err == nil {
		return token, nil
	}
	debugf("DEBUG: Failed to auth at %s: %v\n", config.URL+"/api/security/user/authenticate", err)

	return "", fmt.Errorf("failed to authenticate with Wazuh: %v", err)
}

func tryAuth(config WazuhConfig, url string) (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", err
	}

	// Basic Auth
	auth := base64.StdEncoding.EncodeToString([]byte(config.User + ":" + config.Password))
	req.Header.Add("Authorization", "Basic "+auth)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return "", &AuthError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("failed to authenticate: %s", resp.Status),
		}
	}

	var authResp WazuhAuthResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return "", err
	}

	return authResp.Data.Token, nil
}

// getWazuhAgentsHandler ดึงข้อมูล Agent จาก Wazuh API และส่งกลับให้ Client
func getWazuhAgentsHandler(c *gin.Context) {
	config := getWazuhConfig()
	if config.URL == "" || config.User == "" || config.Password == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Wazuh configuration missing in .env"})
		return
	}

	// 1. Get Token
	token, err := getWazuhToken(config)
	if err != nil {
		// ใช้สถานะจริงจาก Wazuh หากมี
		if ae, ok := err.(*AuthError); ok {
			c.JSON(ae.StatusCode, gin.H{"error": "Failed to authenticate with Wazuh: " + ae.Message})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to authenticate with Wazuh: " + err.Error()})
		return
	}

	// 2. Get Agents
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	// Call Wazuh API to get agents
	// Base URL
	selectFields := c.Query("select")
	if selectFields == "" {
		// ฟิลด์พื้นฐานหากไม่ได้ระบุ
		selectFields = "id,name,ip,status,os.name,os.platform,os.version,version,lastKeepAlive"
	}
	reqUrl := fmt.Sprintf("%s/agents?pretty=true&select=%s", config.URL, selectFields)

	// Add Query Params จาก request เดิม (เช่น ?limit=...&status=...)
	q := c.Request.URL.Query()
	q.Del("select") // ลบออกก่อนเพื่อไม่ให้ซ้ำซ้อนใน RawQuery
	// Support filtering by status (active, disconnected, etc.)
	if status := c.Query("status"); status != "" {
		q.Set("status", status)
	}

	req, err := http.NewRequest("GET", reqUrl, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}
	req.URL.RawQuery = q.Encode()

	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch agents: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response body"})
		return
	}
	debugBody("Wazuh Agents Response", body)

	// เราสามารถ Unmarshal เพื่อตรวจสอบ หรือส่ง Raw JSON กลับไปเลยก็ได้
	// ในที่นี้จะลอง Unmarshal เพื่อให้แน่ใจว่าโครงสร้างถูกต้อง
	var agentResp WazuhAgentResponse
	if err := json.Unmarshal(body, &agentResp); err != nil {
		// ถ้า parse ไม่ได้ อาจเป็น error message จาก Wazuh
		c.Data(resp.StatusCode, "application/json", body)
		return
	}

	c.JSON(http.StatusOK, agentResp)
}

// getWazuhGroupsHandler ดึงรายชื่อกลุ่มทั้งหมดจาก Wazuh
func getWazuhGroupsHandler(c *gin.Context) {
	config := getWazuhConfig()
	token, err := getWazuhToken(config)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to authenticate with Wazuh: " + err.Error()})
		return
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	url := fmt.Sprintf("%s/groups", config.URL)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch groups: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	c.Data(resp.StatusCode, "application/json", body)
}

// getWazuhAgentsByGroupHandler ดึงรายชื่อ Agents ตามกลุ่มที่ระบุ
func getWazuhAgentsByGroupHandler(c *gin.Context) {
	groupName := c.Param("name")
	if groupName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Group name is required"})
		return
	}

	config := getWazuhConfig()
	token, err := getWazuhToken(config)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to authenticate with Wazuh: " + err.Error()})
		return
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	// ใช้ select ตามที่เราเคยทำไว้เพื่อลดขนาดข้อมูล
	selectFields := c.Query("select")
	if selectFields == "" {
		selectFields = "id,name,ip,status"
	}

	url := fmt.Sprintf("%s/agents?group=%s&select=%s", config.URL, groupName, selectFields)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch agents by group: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	c.Data(resp.StatusCode, "application/json", body)
}

// getWazuhAlertsHandler ดึงข้อมูล Security Events (Alerts) จาก Wazuh API
func getWazuhAlertsHandler(c *gin.Context) {
	agentID := c.Query("agent_id")
	groupName := c.Query("group") // รับ group จาก query string
	limitStr := c.Query("limit")
	selectFields := c.Query("select") // ฟิลด์ที่ต้องการ เช่น rule.description,agent.name

	limit := 10000
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 {
			limit = v
		}
	}

	alerts, total, err := fetchIndexerAlerts(agentID, limit, selectFields, groupName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch alerts from indexer: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"total":  total,
	})
}

func executeWazuhActiveResponse(agentID string, command string, custom bool) (int, []byte, error) {
	config := getWazuhConfig()
	if config.URL == "" || (config.Token == "" && (config.User == "" || config.Password == "")) {
		return http.StatusInternalServerError, nil, fmt.Errorf("Wazuh configuration missing in .env")
	}

	token, err := getWazuhToken(config)
	if err != nil {
		return http.StatusUnauthorized, nil, err
	}

	if command == "" {
		return http.StatusBadRequest, nil, fmt.Errorf("command is required")
	}
	if custom && !strings.HasPrefix(command, "!") {
		command = "!" + command
	}

	payloadBytes, _ := json.Marshal(map[string]interface{}{
		"command": command,
		"custom":  custom,
	})

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	url := fmt.Sprintf("%s/active-response?agents_list=%s", config.URL, agentID)
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return http.StatusInternalServerError, nil, err
	}
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return http.StatusInternalServerError, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, body, fmt.Errorf("wazuh returned status %s", resp.Status)
	}

	type activeResponseData struct {
		AffectedItems      []interface{} `json:"affected_items"`
		FailedItems        []interface{} `json:"failed_items"`
		TotalFailedItems   int           `json:"total_failed_items"`
		TotalAffectedItems int           `json:"total_affected_items"`
	}
	var parsed struct {
		Error   int                `json:"error"`
		Message string             `json:"message"`
		Data    activeResponseData `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		if parsed.Error != 0 {
			return resp.StatusCode, body, fmt.Errorf("wazuh active-response error=%d message=%s", parsed.Error, parsed.Message)
		}
		if parsed.Data.TotalFailedItems > 0 || len(parsed.Data.FailedItems) > 0 {
			return resp.StatusCode, body, fmt.Errorf("wazuh active-response failed_items=%d", parsed.Data.TotalFailedItems)
		}
		if len(parsed.Data.AffectedItems) == 0 && parsed.Data.TotalAffectedItems == 0 {
			return resp.StatusCode, body, fmt.Errorf("wazuh active-response affected_items=0")
		}
	}

	return resp.StatusCode, body, nil
}

func executeWazuhStopAgentBestEffort(agentID string, command string, custom bool) (int, []byte, error) {
	if command == "" {
		command = "stop-wazuh-agent"
	}
	return executeWazuhActiveResponse(agentID, command, custom)
}

func executeWazuhRestartAgentBestEffort(agentID string, command string, custom bool) (int, []byte, error) {
	if command == "" {
		command = "restart-wazuh-agent"
	}
	return executeWazuhActiveResponse(agentID, command, custom)
}

// restartWazuhAgentHandler สั่ง Restart Agent
// API: POST /wazuh/agents/:id/restart
// Wazuh: PUT /agents/{agent_id}/restart
func restartWazuhAgentHandler(c *gin.Context) {
	agentID := c.Param("id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Agent ID is required"})
		return
	}

	var input struct {
		Command string `json:"command"`
		Custom  *bool  `json:"custom"`
	}
	_ = c.ShouldBindJSON(&input)

	command := strings.TrimSpace(input.Command)
	if command == "" {
		command = strings.TrimSpace(c.Query("command"))
	}
	if command == "" {
		command = "restart-wazuh-agent"
	}

	custom := true
	if input.Custom != nil {
		custom = *input.Custom
	} else if v := c.Query("custom"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			custom = b
		}
	}
	if input.Custom == nil && c.Query("custom") == "" {
		if command == "restart-wazuh" {
			custom = false
		} else {
			custom = true
		}
	}

	status, body, err := executeWazuhRestartAgentBestEffort(agentID, command, custom)
	if err != nil && status == http.StatusUnauthorized {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to authenticate with Wazuh: " + err.Error()})
		return
	}
	if err != nil && status == http.StatusInternalServerError {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err != nil {
		c.Data(status, "application/json", body)
		return
	}

	c.Data(status, "application/json", body)
}

func stopWazuhAgentBestEffortHandler(c *gin.Context) {
	agentID := c.Param("id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Agent ID is required"})
		return
	}

	var input struct {
		Command string `json:"command"`
		Custom  *bool  `json:"custom"`
	}
	_ = c.ShouldBindJSON(&input)

	command := input.Command
	if command == "" {
		command = c.Query("command")
	}
	if command == "" {
		command = "stop-wazuh-agent"
	}

	custom := true
	if input.Custom != nil {
		custom = *input.Custom
	} else if v := c.Query("custom"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			custom = b
		}
	}
	if input.Custom == nil && c.Query("custom") == "" {
		custom = true
	}

	warning := "Stop is best-effort via Wazuh Active Response. If the agent service stops and goes offline, Wazuh cannot start it again (start requires OS-level access)."

	status, body, err := executeWazuhStopAgentBestEffort(agentID, command, custom)
	if err != nil && status == http.StatusUnauthorized {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to authenticate with Wazuh: " + err.Error()})
		return
	}
	if err != nil && status == http.StatusInternalServerError {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err == nil && obj != nil {
		obj["warning"] = warning
		obj["stop_mode"] = "best_effort_active_response"
		obj["command"] = command
		obj["custom"] = custom
		c.JSON(status, obj)
		return
	}

	c.JSON(status, gin.H{
		"warning":   warning,
		"stop_mode": "best_effort_active_response",
		"command":   command,
		"custom":    custom,
		"response":  string(body),
	})
}

// deleteWazuhAgentHandler ลบ Agent ออกจาก Wazuh
// API: DELETE /wazuh/agents/:id
// Wazuh: DELETE /agents?agents_list={id}
func deleteWazuhAgentHandler(c *gin.Context) {
	agentID := c.Param("id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Agent ID is required"})
		return
	}

	config := getWazuhConfig()
	if config.URL == "" || (config.Token == "" && (config.User == "" || config.Password == "")) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Wazuh configuration missing in .env"})
		return
	}

	// 1. Get Token
	token, err := getWazuhToken(config)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to authenticate with Wazuh: " + err.Error()})
		return
	}

	// 2. Delete Agent
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	// Wazuh API DELETE /agents?agents_list=ID
	// Wazuh ต้องการพารามิเตอร์ status ด้วย: ตัวอย่างเช่น status=all
	status := c.DefaultQuery("status", "all")
	url := fmt.Sprintf("%s/agents?agents_list=%s&status=%s", config.URL, agentID, status)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete agent: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	c.Data(resp.StatusCode, "application/json", body)
}

func renameWazuhAgentHandler(c *gin.Context) {
	agentID := c.Param("id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Agent ID is required"})
		return
	}

	var input struct {
		Name   string `json:"name" binding:"required"`
		IP     string `json:"ip"`
		Status string `json:"status"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Agent name is required"})
		return
	}

	config := getWazuhConfig()
	if config.URL == "" || (config.Token == "" && (config.User == "" || config.Password == "")) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Wazuh configuration missing in .env"})
		return
	}

	token, err := getWazuhToken(config)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to authenticate with Wazuh: " + err.Error()})
		return
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	status := input.Status
	if status == "" {
		status = c.DefaultQuery("status", "all")
	}

	deleteURL := fmt.Sprintf("%s/agents?agents_list=%s&status=%s", config.URL, agentID, status)
	deleteReq, err := http.NewRequest("DELETE", deleteURL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}
	deleteReq.Header.Add("Authorization", "Bearer "+token)

	deleteResp, err := client.Do(deleteReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete agent: " + err.Error()})
		return
	}
	deleteBody, _ := io.ReadAll(deleteResp.Body)
	deleteResp.Body.Close()
	if deleteResp.StatusCode < 200 || deleteResp.StatusCode >= 300 {
		c.Data(deleteResp.StatusCode, "application/json", deleteBody)
		return
	}

	if input.IP == "" {
		input.IP = "any"
	}

	createURL := fmt.Sprintf("%s/agents", config.URL)
	createPayload := map[string]string{
		"name": input.Name,
		"ip":   input.IP,
	}
	createBodyBytes, _ := json.Marshal(createPayload)
	createReq, err := http.NewRequest("POST", createURL, bytes.NewBuffer(createBodyBytes))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}
	createReq.Header.Add("Authorization", "Bearer "+token)
	createReq.Header.Add("Content-Type", "application/json")

	createResp, err := client.Do(createReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create agent: " + err.Error()})
		return
	}
	defer createResp.Body.Close()

	newBody, _ := io.ReadAll(createResp.Body)

	if createResp.StatusCode < 200 || createResp.StatusCode >= 300 {
		c.Data(createResp.StatusCode, "application/json", newBody)
		return
	}

	c.Data(http.StatusOK, "application/json", newBody)
}

// createWazuhAgentHandler เพิ่ม Agent ใหม่ใน Wazuh
// API: POST /wazuh/agents
// Wazuh: POST /agents
func createWazuhAgentHandler(c *gin.Context) {
	var input struct {
		Name string `json:"name" binding:"required"`
		IP   string `json:"ip"` // Optional: "any" or specific IP
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Agent name is required"})
		return
	}

	config := getWazuhConfig()
	token, err := getWazuhToken(config)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to authenticate with Wazuh: " + err.Error()})
		return
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	// Wazuh API POST /agents
	url := fmt.Sprintf("%s/agents", config.URL)

	// Prepare Payload (Wazuh expects name and optional IP)
	// Default IP to "any" if not provided to allow dynamic IP
	if input.IP == "" {
		input.IP = "any"
	}

	reqBody, _ := json.Marshal(input)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create agent: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	c.Data(resp.StatusCode, "application/json", body)
}

func getWazuhAgentByIDHandler(c *gin.Context) {
	agentID := c.Param("id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Agent ID is required"})
		return
	}

	config := getWazuhConfig()
	if config.URL == "" || (config.Token == "" && (config.User == "" || config.Password == "")) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Wazuh configuration missing in .env"})
		return
	}

	token := config.Token
	if token == "" {
		var err error
		token, err = getWazuhToken(config)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to authenticate with Wazuh: " + err.Error()})
			return
		}
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	agentURL := fmt.Sprintf("%s/agents?pretty=true&limit=1&select=id,name,ip,status,os.name,os.platform,os.version,version,lastKeepAlive&q=id=%s", config.URL, agentID)

	reqAgent, err := http.NewRequest("GET", agentURL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	reqAgent.Header.Add("Authorization", "Bearer "+token)

	respAgent, err := client.Do(reqAgent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch agent: " + err.Error()})
		return
	}
	defer respAgent.Body.Close()

	agentBody, err := io.ReadAll(respAgent.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read agent response"})
		return
	}

	var agentResp WazuhAgentResponse
	if err := json.Unmarshal(agentBody, &agentResp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse agent response"})
		return
	}

	logsLimitStr := c.Query("logs_limit")
	selectFields := c.Query("select") // เลือกฟิลด์สำหรับ alerts
	logsLimit := 10000
	if logsLimitStr != "" {
		if v, err := strconv.Atoi(logsLimitStr); err == nil && v > 0 {
			logsLimit = v
		}
	}

	alerts, total, err := fetchIndexerAlerts(agentID, logsLimit, selectFields, "")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch alerts from indexer: " + err.Error()})
		return
	}

	result := gin.H{
		"agent":       nil,
		"alerts":      alerts,
		"alerts_meta": total,
	}

	if len(agentResp.Data.AffectedItems) > 0 {
		result["agent"] = agentResp.Data.AffectedItems[0]
	}

	c.JSON(http.StatusOK, result)
}
