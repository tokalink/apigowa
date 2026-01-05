package api

import (
	"apiwago/internal/whatsapp"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"

	"os"
	"strings"

	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/skip2/go-qrcode"
)

type Server struct {
	Service *whatsapp.Service
}

func NewServer(service *whatsapp.Service) *Server {
	return &Server{Service: service}
}

// FlexString handles both JSON string and number for string fields
type FlexString string

func (fs *FlexString) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*fs = FlexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err == nil {
		*fs = FlexString(n.String())
		return nil
	}
	return nil
}

// ... LoginHandler and SendMessageHandler ...

type StartSessionRequest struct {
	Token              FlexString `json:"token"`
	RejectCall         string     `json:"reject_call"`
	RejectExcludePhone []string   `json:"reject_exclude_phone"`
	RejectMessage      string     `json:"reject_message"`
}

func (s *Server) StartSessionHandler(c *gin.Context) {
	var req StartSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	config := whatsapp.RejectionConfig{
		RejectCall:         req.RejectCall,
		RejectExcludePhone: req.RejectExcludePhone,
		RejectMessage:      req.RejectMessage,
	}

	if err := s.Service.StartSession(string(req.Token), config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"message": "Session started",
	})
}

func (s *Server) LoginHandler(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	qrBytes, err := s.Service.Login(token)
	if err != nil {
		if err.Error() == "loggedin" {
			c.JSON(http.StatusOK, gin.H{"status": "already_logged_in"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Data(http.StatusOK, "image/png", qrBytes)
}

func (s *Server) LoginStreamHandler(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	// Set headers for SSE
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("Transfer-Encoding", "chunked")

	qrChan := make(chan string)

	// Run LoginStream in goroutine
	// Run LoginStream in goroutine
	// and capture error
	errChan := make(chan error, 1)
	go func() {
		defer close(qrChan)
		err := s.Service.LoginStream(c.Request.Context(), token, qrChan)
		if err != nil {
			errChan <- err
		}
	}()

	// Stream events
	c.Stream(func(w io.Writer) bool {
		select {
		case code, ok := <-qrChan:
			if ok {
				// Generate PNG for the code
				png, _ := qrcode.Encode(code, qrcode.Medium, 256)
				base64Img := base64.StdEncoding.EncodeToString(png)
				c.SSEvent("qr", base64Img)
				return true
			}
			// Channel closed - check if it was due to timeout
			select {
			case err := <-errChan:
				if err == whatsapp.ErrQRTimeout {
					c.SSEvent("timeout", "Session expired")
				}
			default:
				// Normal closure or other error
				c.SSEvent("status", "closed")
			}
			return false
		case err := <-errChan:
			// Error happened while waiting?
			if err == whatsapp.ErrQRTimeout {
				c.SSEvent("timeout", "Session expired")
			}
			return false
		case <-c.Done():
			return false
		}
	})
}

type SendMessageRequest struct {
	Token    FlexString `json:"token"`
	Phone    string     `json:"phone"`
	Message  string     `json:"message"`
	FileUrl  string     `json:"file_url"`
	FileName string     `json:"file_name"`
}

func (s *Server) SendMessageHandler(c *gin.Context) {
	var req SendMessageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	// Format Phone to JID if needed
	jid := req.Phone
	if jid != "" && !strings.Contains(jid, "@") {
		jid = jid + "@s.whatsapp.net"
	}

	var msgID string
	var err error

	if req.FileUrl != "" {
		msgID, err = s.Service.SendMedia(string(req.Token), jid, req.FileUrl, req.Message, req.FileName)
	} else {
		msgID, err = s.Service.SendMessage(string(req.Token), jid, req.Message)
	}

	if err != nil {
		if err == whatsapp.ErrUserNotRegistered {
			c.JSON(http.StatusOK, gin.H{
				"status":  false,
				"token":   req.Token,
				"phone":   req.Phone,
				"message": "Belum Terdaftar",
				"data":    []interface{}{},
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  true,
		"phone":   req.Phone,
		"message": "Terkirim",
		"data": gin.H{
			"id":     msgID,
			"status": true,
		},
	})
}

type PairPhoneRequest struct {
	Token FlexString `json:"token"`
	Phone string     `json:"phone"`
}

func (s *Server) PairPhoneHandler(c *gin.Context) {
	var req PairPhoneRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	code, err := s.Service.PairPhone(string(req.Token), req.Phone)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": code})
}

func (s *Server) GetContactsHandler(c *gin.Context) {
	token := c.Query("token")
	contacts, err := s.Service.GetContacts(token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, contacts)
}

func (s *Server) GetGroupsHandler(c *gin.Context) {
	token := c.Query("token")
	groups, err := s.Service.GetGroups(token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, groups)
}

type StatusRequest struct {
	Token FlexString `json:"token"`
}

func (s *Server) StatusHandler(c *gin.Context) {
	var req StatusRequest

	// Try binding JSON first
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err != nil && err != io.EOF {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	// Fallback to query param if token not in body
	if req.Token == "" {
		req.Token = FlexString(c.Query("token"))
	}

	if req.Token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	status, err := s.Service.GetStatus(string(req.Token))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Custom Response Format
	resp := gin.H{
		"status":  status.IsLoggedIn,
		"message": "DISCONNECTED",
		"pic":     status.ProfilePicURL,
		"name":    status.Name,
		"phone":   status.Phone,
		"data":    nil,
	}

	if status.IsLoggedIn {
		resp["message"] = "AUTHENTICATED"
		resp["data"] = gin.H{
			"id":   status.JID, // Already formatted?
			"lid":  "",         // LID not explicitly fetched usually, unless we have it
			"name": status.Name,
		}
		// If JID has AD part, maybe we want to show it?
		// status.JID from service is usually full JID string.
	}

	c.JSON(http.StatusOK, resp)
}

type QRCodeRequest struct {
	Token FlexString `json:"token"`
}

func (s *Server) QRCodeHandler(c *gin.Context) {
	var req QRCodeRequest

	// User requested to get token from JSON body even for GET requests
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	qrBytes, err := s.Service.Login(string(req.Token))
	if err != nil {
		errMsg := err.Error()
		// Jika sudah login, kembalikan respons seperti /api/status
		if strings.Contains(errMsg, "already logged in") {
			status, statusErr := s.Service.GetStatus(string(req.Token))
			if statusErr != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": statusErr.Error()})
				return
			}

			resp := gin.H{
				"status":  status.IsLoggedIn,
				"message": "AUTHENTICATED",
				"pic":     status.ProfilePicURL,
				"name":    status.Name,
				"phone":   status.Phone,
				"data": gin.H{
					"id":   status.JID,
					"lid":  "",
					"name": status.Name,
				},
			}
			c.JSON(http.StatusOK, resp)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": errMsg})
		return
	}

	base64Img := base64.StdEncoding.EncodeToString(qrBytes)

	c.JSON(http.StatusOK, gin.H{
		"status": true,
		"qrcode": "data:image/png;base64," + base64Img,
	})
}

func (s *Server) LogoutHandler(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	if err := s.Service.Logout(token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "logged_out"})
}

func (s *Server) ReconnectHandler(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	if err := s.Service.Reconnect(token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "reconnected"})
}

// Admin / Auth Handlers

type SetupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) SetupHandler(c *gin.Context) {
	isSetup, err := s.Service.Store.IsSetupDetails()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if isSetup {
		c.JSON(http.StatusForbidden, gin.H{"error": "already setup"})
		return
	}

	var req SetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Username == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username and password required"})
		return
	}

	if err := s.Service.Store.SetCredentials(req.Username, req.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "setup_complete"})
}

func (s *Server) CheckSetupHandler(c *gin.Context) {
	isSetup, err := s.Service.Store.IsSetupDetails()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"is_setup": isSetup})
}

func (s *Server) LoginAdminHandler(c *gin.Context) {
	var req SetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	valid, err := s.Service.Store.CheckCredentials(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Set simple cookie
	c.SetCookie("auth_session", "admin", 3600*24, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"status": "logged_in"})
}

func (s *Server) LogoutAdminHandler(c *gin.Context) {
	c.SetCookie("auth_session", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"status": "logged_out"})
}

func (s *Server) ListDevicesHandler(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	search := c.Query("q")
	workspace := c.Query("workspace") // Added workspace query parameter

	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 10
	}

	offset := (page - 1) * limit

	devices, total, err := s.Service.Store.GetDevices(limit, offset, search, workspace) // Pass workspace to service
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  devices,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

func (s *Server) GetWorkspacesHandler(c *gin.Context) {
	workspaces, err := s.Service.GetWorkspaces()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": workspaces})
}

func (s *Server) DeleteDeviceHandler(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token required"})
		return
	}

	if err := s.Service.DeleteClient(token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func (s *Server) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie("auth_session")
		if err != nil || cookie != "admin" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func (s *Server) APIKeyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Check if authenticated via Cookie (Admin Dashboard)
		cookie, err := c.Cookie("auth_session")
		if err == nil && cookie == "admin" {
			c.Next()
			return
		}

		// 2. Check API Key (External Access)
		apiKey := os.Getenv("APIKEY")
		if apiKey != "" {
			reqKey := c.GetHeader("apikey")
			if reqKey == apiKey {
				c.Next()
				return
			}
		}

		// 3. Default: Unauthorized
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		c.Abort()
	}
}

func (s *Server) RegisterRoutes(r *gin.Engine) {
	api := r.Group("/api")
	{
		api.GET("/login", s.LoginHandler) // Legacy/QR
		api.GET("/login-sse", s.LoginStreamHandler)
		api.POST("/pair", s.PairPhoneHandler)
		api.POST("/send", s.SendMessageHandler)
		api.GET("/contacts", s.GetContactsHandler)
		api.GET("/groups", s.GetGroupsHandler)
		api.POST("/logout", s.LogoutHandler)
		api.POST("/reconnect", s.ReconnectHandler)
		api.Any("/status", s.StatusHandler) // Support GET & POST

		// Admin Routes
		api.POST("/setup", s.SetupHandler)
		api.GET("/check-setup", s.CheckSetupHandler)
		api.POST("/login-admin", s.LoginAdminHandler)
		api.POST("/logout-admin", s.LogoutAdminHandler)

		authorized := api.Group("/")
		authorized.Use(s.APIKeyMiddleware())
		{
			authorized.POST("/start", s.StartSessionHandler)
			authorized.POST("/qrcode", s.QRCodeHandler)
			authorized.GET("/qrcode", s.QRCodeHandler)
			authorized.GET("/devices", s.ListDevicesHandler) // Protected
			authorized.DELETE("/device", s.DeleteDeviceHandler)
			authorized.POST("/webhook", s.UpdateWebhookHandler)
			authorized.GET("/workspaces", s.GetWorkspacesHandler) // Protected
			authorized.POST("/workspace", s.UpdateWorkspaceHandler)
		}
	}

	// Legacy support or direct access
	r.GET("/login", s.LoginHandler)
	r.POST("/send", s.SendMessageHandler)
}

// ... Handler Definitions ...

type UpdateWorkspaceRequest struct {
	Token     FlexString `json:"token"`
	Workspace string     `json:"workspace"`
}

func (s *Server) UpdateWorkspaceHandler(c *gin.Context) {
	var req UpdateWorkspaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	if err := s.Service.UpdateWorkspace(string(req.Token), req.Workspace); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":    true,
		"token":     req.Token,
		"workspace": req.Workspace,
	})
}

type UpdateWebhookRequest struct {
	Token string `json:"token"`
	URL   string `json:"url"`
}

func (s *Server) UpdateWebhookHandler(c *gin.Context) {
	var req UpdateWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	if err := s.Service.Store.UpdateWebhook(req.Token, req.URL); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "updated", "url": req.URL})
}
