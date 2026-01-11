package whatsapp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"apiwago/pkg/store"

	"github.com/skip2/go-qrcode"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"
)

type Service struct {
	mu               sync.RWMutex
	clientPool       *ClientPool
	RejectionConfigs map[string]RejectionConfig
	QRCodes          map[string]string
	Store            *store.Store
	WebhookURL       string
	workerPool       *WorkerPool
	httpClient       *HTTPClientPool
}

type RejectionConfig struct {
	RejectCall         string   `json:"reject_call"`          // "Y" or "N"
	RejectExcludePhone []string `json:"reject_exclude_phone"` // List of JIDs or phones
	RejectMessage      string   `json:"reject_message"`
}

func NewService(s *store.Store, webhookURL string) *Service {
	// Load pool configuration from environment
	poolCfg := NewPoolConfigFromEnv()

	return &Service{
		Store:            s,
		clientPool:       NewClientPool(poolCfg),
		RejectionConfigs: make(map[string]RejectionConfig),
		QRCodes:          make(map[string]string),
		WebhookURL:       webhookURL,
		workerPool:       NewWorkerPool(poolCfg.WorkerPoolSize),
		httpClient:       NewHTTPClientPool(poolCfg.HTTPPoolSize),
	}
}

// Close cleans up resources
func (s *Service) Close() {
	s.clientPool.Stop()
	s.workerPool.Stop()
}

// AutoReconnect connects all previously logged-in accounts
// Call this after creating the service to auto-reconnect on startup
func (s *Service) AutoReconnect() {
	tokens, err := s.Store.GetLoggedInTokens()
	if err != nil {
		fmt.Printf("[AutoReconnect] Failed to get logged-in tokens: %v\n", err)
		return
	}

	if len(tokens) == 0 {
		fmt.Println("[AutoReconnect] No logged-in accounts to reconnect")
		return
	}

	fmt.Printf("[AutoReconnect] Reconnecting %d accounts...\n", len(tokens))

	// Reconnect each token in a goroutine
	for _, token := range tokens {
		go func(t string) {
			client, err := s.GetClient(t)
			if err != nil {
				fmt.Printf("[AutoReconnect] Failed to get client for %s: %v\n", t, err)
				return
			}

			// Only connect if has valid stored session
			if client.Store.ID != nil {
				if !client.IsConnected() {
					if err := client.Connect(); err != nil {
						fmt.Printf("[AutoReconnect] Failed to connect %s: %v\n", t, err)
					} else {
						fmt.Printf("[AutoReconnect] Connected: %s\n", t)
					}
				}
			}
		}(token)
	}
}

// StartPeriodicCheck starts a background routine to check connectivity
// of logged-in accounts periodically
func (s *Service) StartPeriodicCheck(ctx context.Context) {
	// Default interval 2 minutes, or from env
	interval := 2 * time.Minute
	if envInterval := os.Getenv("RECONNECT_INTERVAL"); envInterval != "" {
		if d, err := time.ParseDuration(envInterval); err == nil {
			interval = d
		}
	}

	fmt.Printf("[StartPeriodicCheck] Starting periodic check every %v\n", interval)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.checkConnectivity()
			}
		}
	}()
}

// checkConnectivity reconnects disconnected sessions
func (s *Service) checkConnectivity() {
	tokens, err := s.Store.GetLoggedInTokens()
	if err != nil {
		fmt.Printf("[PeriodicCheck] Failed to get logged-in tokens: %v\n", err)
		return
	}

	for _, token := range tokens {
		// Only check/reconnect if we can get the client
		client, err := s.GetClient(token)
		if err != nil {
			continue
		}

		// Skip if not logged in (QR not scanned yet)
		if client.Store.ID == nil {
			continue
		}

		// If logged in but disconnected, reconnect
		if !client.IsConnected() {
			fmt.Printf("[PeriodicCheck] Token %s is logged in but disconnected. Reconnecting...\n", token)
			if err := client.Connect(); err != nil {
				fmt.Printf("[PeriodicCheck] Failed to reconnect %s: %v\n", token, err)
			} else {
				fmt.Printf("[PeriodicCheck] Successfully reconnected %s\n", token)
			}
		}
	}
}

func (s *Service) GetClient(token string) (*whatsmeow.Client, error) {
	// Try to get from pool first
	if client := s.clientPool.Get(token); client != nil {
		return client, nil
	}

	// Not in pool, need to create
	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring lock
	if client := s.clientPool.Get(token); client != nil {
		return client, nil
	}

	device, err := s.Store.GetDevice(token)
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	// Create client
	client := whatsmeow.NewClient(device, nil) // Logging nil for now

	// Add event handler
	client.AddEventHandler(func(evt interface{}) {
		s.handleEvent(token, client, evt)
	})

	// Add to pool
	s.clientPool.Put(token, client)

	return client, nil
}

// handleEvent processes WhatsApp events using the worker pool
func (s *Service) handleEvent(token string, client *whatsmeow.Client, evt interface{}) {
	switch v := evt.(type) {
	case *events.PairSuccess:
		s.workerPool.Submit(func() {
			fmt.Printf("Token %s paired successfully with JID %s\n", token, v.ID)
			pushName := ""
			if client.Store.PushName != "" {
				pushName = client.Store.PushName
			}
			s.Store.UpdateTokenJID(token, v.ID, pushName)
		})

	case *events.CallOffer:
		s.workerPool.Submit(func() {
			s.handleCallRejection(token, v, client)
		})

	case *events.PushName:
		s.workerPool.Submit(func() {
			if client.Store.ID != nil && v.JID.User == client.Store.ID.User {
				if v.Message != nil && v.OldPushName != v.NewPushName {
					s.Store.UpdateTokenJID(token, *client.Store.ID, v.NewPushName)
				}
			}
		})

	case *events.Connected:
		s.workerPool.Submit(func() {
			s.handleConnected(token, client)
		})

	case *events.Message:
		s.workerPool.Submit(func() {
			s.handleMessage(token, client, v)
		})
	}
}

// handleConnected syncs name to database on connection
func (s *Service) handleConnected(token string, client *whatsmeow.Client) {
	// Wait briefly for PushName to be available
	time.Sleep(2 * time.Second)

	if client.Store.ID == nil {
		return
	}

	pushName := client.Store.PushName
	phoneNumber := client.Store.ID.User

	if pushName == "" {
		pushName = phoneNumber
	}

	// Don't overwrite existing name with phone number
	if pushName == phoneNumber {
		dbInfo, err := s.Store.GetDeviceInfo(token)
		if err == nil && dbInfo != nil && dbInfo.Name != "" && dbInfo.Name != phoneNumber {
			fmt.Printf("Token %s: Connected - nama sudah ada di DB: %s, skip update\n", token, dbInfo.Name)
			return
		}
	}

	s.Store.UpdateTokenJID(token, *client.Store.ID, pushName)
	fmt.Printf("Token %s: Connected - nama disinkronkan ke database: %s\n", token, pushName)
}

// handleMessage processes incoming messages
func (s *Service) handleMessage(token string, client *whatsmeow.Client, v *events.Message) {
	if v.Info.IsFromMe {
		return
	}

	msgText := v.Message.GetConversation()
	if msgText == "" {
		msgText = v.Message.GetExtendedTextMessage().GetText()
	}

	if msgText == "!ping" {
		s.SendMessage(token, v.Info.Chat.String(), "pong")
	} else if msgText == "!id" {
		workspace := "default"
		deviceInfo, err := s.Store.GetDeviceInfo(token)
		if err == nil && deviceInfo.Workspace != "" {
			workspace = deviceInfo.Workspace
		}

		reply := ""
		if v.Info.IsGroup {
			reply += fmt.Sprintf("Group ID : %s\n", v.Info.Chat.String())
		}
		reply += fmt.Sprintf("Your ID : %s\nMID : %s\nworkspace : %s\nid : %s",
			v.Info.Sender.String(),
			v.Info.ID,
			workspace,
			token,
		)
		s.SendMessage(token, v.Info.Chat.String(), reply)
	}

	// Handle webhook
	s.handleWebhookEvent(token, v)
}

func (s *Service) consumeQR(token string, qrChan <-chan whatsmeow.QRChannelItem) {
	for evt := range qrChan {
		if evt.Event == "code" {
			s.mu.Lock()
			s.QRCodes[token] = evt.Code
			s.mu.Unlock()
			fmt.Printf("Token %s: QR code diterima dan di-cache\n", token)
		} else if evt.Event == "success" {
			fmt.Printf("Token %s: Login berhasil!\n", token)
			s.mu.Lock()
			delete(s.QRCodes, token)
			s.mu.Unlock()
			return
		} else {
			fmt.Printf("Token %s: QR event: %s\n", token, evt.Event)
		}
	}

	// Channel closed
	s.mu.Lock()
	delete(s.QRCodes, token)
	s.mu.Unlock()
	fmt.Printf("Token %s: QR channel ditutup, cache dibersihkan\n", token)

	// Disconnect if not logged in
	if client := s.clientPool.Get(token); client != nil && client.Store.ID == nil {
		fmt.Printf("Token %s: Timeout 60 detik, session di-disconnect\n", token)
		client.Disconnect()
	}
}

func (s *Service) StartSession(token string, config RejectionConfig) error {
	s.mu.Lock()
	s.RejectionConfigs[token] = config
	s.mu.Unlock()

	client, err := s.GetClient(token)
	if err != nil {
		return err
	}

	// Force reconnect if stuck
	if client.IsConnected() && client.Store.ID == nil {
		fmt.Printf("Token %s stuck (connected=true, loggedin=false). Force reconnecting...\n", token)
		client.Disconnect()
	}

	if !client.IsConnected() {
		qrChan, _ := client.GetQRChannel(context.Background())
		go s.consumeQR(token, qrChan)
		return client.Connect()
	}
	return nil
}

func (s *Service) handleCallRejection(token string, evt *events.CallOffer, client *whatsmeow.Client) {
	s.mu.RLock()
	config, ok := s.RejectionConfigs[token]
	s.mu.RUnlock()

	if !ok || config.RejectCall != "Y" {
		return
	}

	caller := evt.CallCreator.User
	for _, excluded := range config.RejectExcludePhone {
		if excluded == caller {
			return
		}
	}

	err := client.RejectCall(context.Background(), evt.CallCreator, evt.CallID)
	if err != nil {
		fmt.Printf("Failed to reject call from %s: %v\n", caller, err)
	} else {
		fmt.Printf("Rejected call from %s\n", caller)
	}

	if config.RejectMessage != "" {
		s.SendMessage(token, evt.CallCreator.String(), config.RejectMessage)
	}
}

func (s *Service) DeleteClient(token string) error {
	// Remove from pool (this will disconnect)
	s.clientPool.Remove(token)

	// Clean up rejection config and QR
	s.mu.Lock()
	delete(s.RejectionConfigs, token)
	delete(s.QRCodes, token)
	s.mu.Unlock()

	return s.Store.DeleteDevice(token)
}

func (s *Service) handleWebhookEvent(token string, evt interface{}) {
	webhookURL, err := s.Store.GetWebhook(token)
	if err != nil || webhookURL == "" {
		webhookURL = s.WebhookURL
	}

	if webhookURL == "" {
		return
	}

	var payload map[string]interface{}

	switch v := evt.(type) {
	case *events.Message:
		// Get phone number from sender (remove @s.whatsapp.net suffix)
		phone := v.Info.Sender.User

		// Get message text
		msgText := v.Message.GetConversation()
		if msgText == "" {
			msgText = v.Message.GetExtendedTextMessage().GetText()
		}

		// Determine message type
		msgType := "conversation"
		if v.Message.GetImageMessage() != nil {
			msgType = "image"
		} else if v.Message.GetVideoMessage() != nil {
			msgType = "video"
		} else if v.Message.GetAudioMessage() != nil {
			msgType = "audio"
		} else if v.Message.GetDocumentMessage() != nil {
			msgType = "document"
		} else if v.Message.GetStickerMessage() != nil {
			msgType = "sticker"
		} else if v.Message.GetExtendedTextMessage() != nil {
			msgType = "extendedText"
		}

		// Build original message structure for "messages" field
		originalMessage := []map[string]interface{}{
			{
				"key": map[string]interface{}{
					"remoteJid": v.Info.Chat.String(),
					"fromMe":    v.Info.IsFromMe,
					"id":        v.Info.ID,
				},
				"messageTimestamp": v.Info.Timestamp.Unix(),
				"pushName":         v.Info.PushName,
				"broadcast":        v.Info.IsGroup,
				"message":          v.Message,
			},
		}

		// Convert original message to JSON string
		messagesJSON, _ := json.Marshal(originalMessage)

		payload = map[string]interface{}{
			"token":     token,
			"event":     "message",
			"phone":     phone,
			"fromMe":    v.Info.IsFromMe,
			"pushName":  v.Info.PushName,
			"text":      msgText,
			"messages":  string(messagesJSON),
			"type":      msgType,
			"update_at": time.Now().Format("2006-01-02 15:04:05"),
			"message":   "Hello from Whatsapp Callback",
		}

	case *events.Receipt:
		payload = map[string]interface{}{
			"token":     token,
			"event":     "receipt",
			"chat":      v.Chat.String(),
			"sender":    v.Sender.String(),
			"timestamp": v.Timestamp.Unix(),
			"type":      string(v.Type),
			"ids":       v.MessageIDs,
			"update_at": time.Now().Format("2006-01-02 15:04:05"),
		}

	default:
		return
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Failed to marshal webhook payload: %v\n", err)
		return
	}

	// Use pooled HTTP client
	resp, err := s.httpClient.Get().Post(webhookURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		fmt.Printf("Failed to send webhook to %s: %v\n", webhookURL, err)
		return
	}
	defer resp.Body.Close()
}

func (s *Service) Login(token string) ([]byte, error) {
	client, err := s.GetClient(token)
	if err != nil {
		return nil, err
	}

	if client.Store.ID != nil {
		return nil, fmt.Errorf("already logged in as %s", client.Store.ID)
	}

	s.mu.RLock()
	code, ok := s.QRCodes[token]
	s.mu.RUnlock()

	if ok && code != "" {
		png, err := qrcode.Encode(code, qrcode.Medium, 256)
		return png, err
	}

	if client.IsConnected() {
		return nil, fmt.Errorf("waiting_for_qr")
	}

	return nil, fmt.Errorf("not_connected")
}

var ErrQRTimeout = fmt.Errorf("qr_timeout")

func (s *Service) LoginStream(ctx context.Context, token string, qrStream chan<- string) error {
	client, err := s.GetClient(token)
	if err != nil {
		return err
	}

	if client.Store.ID != nil {
		return fmt.Errorf("already_logged_in")
	}

	if !client.IsConnected() || (client.IsConnected() && client.Store.ID == nil) {
		err := s.StartSession(token, RejectionConfig{})
		if err != nil {
			return err
		}
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var lastCode string
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if client.Store.ID != nil {
				return nil
			}

			if !client.IsConnected() {
				return fmt.Errorf("disconnected")
			}

			s.mu.RLock()
			code, ok := s.QRCodes[token]
			s.mu.RUnlock()

			if ok && code != "" && code != lastCode {
				qrStream <- code
				lastCode = code
			}
		case <-timeoutCtx.Done():
			return ErrQRTimeout
		case <-ctx.Done():
			return nil
		}
	}
}

var ErrUserNotRegistered = fmt.Errorf("user not registered on WhatsApp")

// Pre-compiled regex for phone normalization
var phoneCleanRegex = regexp.MustCompile(`[^0-9]`)

// NormalizePhone normalizes phone number to WhatsApp format
// - Removes ALL non-numeric characters (including +, -, spaces, parentheses, etc.)
// - Converts 08xxx to 628xxx
func NormalizePhone(phone string) string {
	original := phone

	// Remove ALL non-numeric characters
	phone = phoneCleanRegex.ReplaceAllString(phone, "")

	// Convert 08 prefix to 628 (Indonesian format)
	if strings.HasPrefix(phone, "08") {
		phone = "62" + phone[1:]
	}

	// Handle case where someone put 0628 or similar (after removing +)
	if strings.HasPrefix(phone, "0") && len(phone) > 1 {
		phone = phone[1:]
	}

	// Print to console for debugging
	fmt.Printf("[NormalizePhone] %s -> %s\n", original, phone)
	return phone
}

func (s *Service) SendMessage(token, to, text string) (string, error) {
	client, err := s.GetClient(token)
	if err != nil {
		return "", err
	}

	if !client.IsConnected() {
		return "", fmt.Errorf("client not logged in")
	}

	// Normalize phone number if not already a JID
	if !strings.Contains(to, "@") {
		normalized := NormalizePhone(to)
		fmt.Printf("[SendMessage] Normalized phone: %s -> %s\n", to, normalized)
		to = normalized + "@s.whatsapp.net"
	}
	recipient, err := types.ParseJID(to)
	if err != nil {
		return "", fmt.Errorf("invalid recipient JID: %w", err)
	}

	// Check if registered on WhatsApp (skip for groups)
	// Can be disabled with SKIP_ISONWHATSAPP=true in .env
	skipCheck := os.Getenv("SKIP_ISONWHATSAPP") == "true"
	if recipient.Server != "g.us" && !skipCheck {
		// For IsOnWhatsApp, we need to send number WITHOUT country code
		// because WhatsApp will add country code automatically based on account region
		phoneToCheck := recipient.User
		// Strip Indonesian country code (62) if present to avoid double 62
		if strings.HasPrefix(phoneToCheck, "62") && len(phoneToCheck) > 2 {
			phoneToCheck = phoneToCheck[2:]
		}

		fmt.Printf("[SendMessage] IsOnWhatsApp checking: %s (from %s)\n", phoneToCheck, recipient.User)

		// Use 30 second timeout for IsOnWhatsApp check
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		isOnWhatsApp, err := client.IsOnWhatsApp(ctx, []string{phoneToCheck})
		cancel() // Cancel immediately after call

		if err != nil {
			// Log the error but don't fail - try to send anyway
			fmt.Printf("[SendMessage] IsOnWhatsApp check failed for %s: %v (akan tetap coba kirim)\n", phoneToCheck, err)
		} else if len(isOnWhatsApp) > 0 {
			fmt.Printf("[SendMessage] IsOnWhatsApp result for %s: IsIn=%v, JID=%s\n",
				phoneToCheck, isOnWhatsApp[0].IsIn, isOnWhatsApp[0].JID.String())
			if !isOnWhatsApp[0].IsIn {
				return "", ErrUserNotRegistered
			}
		} else {
			fmt.Printf("[SendMessage] IsOnWhatsApp returned empty result for %s (akan tetap coba kirim)\n", phoneToCheck)
		}
	}

	msg := &waE2E.Message{
		Conversation: proto.String(text),
	}

	// Send with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.SendMessage(ctx, recipient, msg)
	if err != nil {
		// Check if it's a "not registered" error from WhatsApp
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "not on whatsapp") || strings.Contains(errStr, "unknown user") || strings.Contains(errStr, "recipient not found") {
			return "", ErrUserNotRegistered
		}
		return "", err
	}
	return resp.ID, nil
}

func (s *Service) PairPhone(token, phone string) (string, error) {
	client, err := s.GetClient(token)
	if err != nil {
		return "", err
	}

	if client.Store.ID != nil {
		return "", fmt.Errorf("already logged in")
	}

	if !client.IsConnected() {
		if err := client.Connect(); err != nil {
			return "", err
		}
	}

	time.Sleep(1 * time.Second)

	browserName := os.Getenv("DEVICE_NAME")
	if browserName == "" {
		browserName = "Chrome"
	}

	fmt.Printf("[PairPhone] Phone: %s, Browser: %s\n", phone, browserName)

	code, err := client.PairPhone(context.Background(), phone, true, whatsmeow.PairClientChrome, browserName)
	if err != nil {
		return "", err
	}

	return code, nil
}

func (s *Service) GetContacts(token string) (map[types.JID]types.ContactInfo, error) {
	client, err := s.GetClient(token)
	if err != nil {
		return nil, err
	}

	if client.Store == nil || client.Store.Contacts == nil {
		return nil, fmt.Errorf("contacts store not initialized")
	}

	return client.Store.Contacts.GetAllContacts(context.Background())
}

func (s *Service) GetGroups(token string) ([]*types.GroupInfo, error) {
	client, err := s.GetClient(token)
	if err != nil {
		return nil, err
	}

	if !client.IsConnected() {
		if client.Store.ID != nil {
			client.Connect()
			time.Sleep(1 * time.Second)
		} else {
			return nil, fmt.Errorf("client not logged in")
		}
	}

	return client.GetJoinedGroups(context.Background())
}

type SessionStatus struct {
	IsLoggedIn    bool   `json:"is_logged_in"`
	JID           string `json:"jid,omitempty"`
	Name          string `json:"name,omitempty"`
	Phone         string `json:"phone,omitempty"`
	ProfilePicURL string `json:"profile_pic_url,omitempty"`
}

func (s *Service) GetStatus(token string) (*SessionStatus, error) {
	client, err := s.GetClient(token)
	if err != nil {
		return nil, err
	}

	if !client.IsConnected() {
		if client.Store.ID != nil {
			go client.Connect()
			time.Sleep(500 * time.Millisecond)
		}
	}

	dbInfo, _ := s.Store.GetDeviceInfo(token)

	status := &SessionStatus{
		IsLoggedIn: client.Store.ID != nil,
	}

	if dbInfo != nil {
		status.Name = dbInfo.Name
	}

	if client.Store.ID != nil {
		status.JID = client.Store.ID.String()
		status.Phone = client.Store.ID.User
		if status.Name == "" {
			status.Name = client.Store.PushName
		}

		if (dbInfo == nil || dbInfo.Name == "") && client.Store.PushName != "" && client.Store.PushName != client.Store.ID.User {
			go s.Store.UpdateTokenJID(token, *client.Store.ID, client.Store.PushName)
			fmt.Printf("Token %s: GetStatus - sinkronkan nama ke database: %s\n", token, client.Store.PushName)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		ppJID := client.Store.ID.ToNonAD()
		pic, err := client.GetProfilePictureInfo(ctx, ppJID, &whatsmeow.GetProfilePictureParams{
			Preview: true,
		})
		if err != nil {
			fmt.Printf("Failed to get profile picture for %s: %v\n", ppJID, err)
		} else if pic != nil {
			status.ProfilePicURL = pic.URL
		}
	}

	return status, nil
}

func (s *Service) ListDevices(page, limit int, search, workspace string) ([]store.DeviceSummary, int, error) {
	return s.Store.GetDevices(limit, (page-1)*limit, search, workspace)
}

func (s *Service) UpdateWorkspace(token, workspace string) error {
	return s.Store.UpdateWorkspace(token, workspace)
}

func (s *Service) GetWorkspaces() ([]string, error) {
	return s.Store.GetWorkspaces()
}

func (s *Service) Logout(token string) error {
	client, err := s.GetClient(token)
	if err != nil {
		return err
	}
	if client.Store.ID == nil {
		return fmt.Errorf("not logged in")
	}

	if err := client.Logout(context.Background()); err != nil {
		return fmt.Errorf("failed to logout: %w", err)
	}

	s.Store.ClearTokenJID(token)

	// Remove from pool
	s.clientPool.Remove(token)

	s.mu.Lock()
	delete(s.QRCodes, token)
	s.mu.Unlock()

	return nil
}

func (s *Service) Reconnect(token string) error {
	client, err := s.GetClient(token)
	if err != nil {
		return err
	}

	if client.IsConnected() {
		client.Disconnect()
	}

	time.Sleep(500 * time.Millisecond)

	if err := client.Connect(); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	return nil
}

func (s *Service) SendMedia(token, to, url, caption, fileName string) (string, error) {
	client, err := s.GetClient(token)
	if err != nil {
		return "", err
	}

	if !client.IsConnected() {
		if client.Store.ID != nil {
			client.Connect()
			time.Sleep(1 * time.Second)
		} else {
			return "", fmt.Errorf("client not logged in")
		}
	}

	// Normalize phone number if not already a JID
	if !strings.Contains(to, "@") {
		normalized := NormalizePhone(to)
		fmt.Printf("[SendMedia] Normalized phone: %s -> %s\n", to, normalized)
		to = normalized + "@s.whatsapp.net"
	}
	recipient, err := types.ParseJID(to)
	if err != nil {
		return "", fmt.Errorf("invalid recipient JID: %w", err)
	}

	// Check if registered on WhatsApp (skip for groups)
	skipCheck := os.Getenv("SKIP_ISONWHATSAPP") == "true"
	if recipient.Server != "g.us" && !skipCheck {
		// For IsOnWhatsApp, we need to send number WITHOUT country code
		// because WhatsApp will add country code automatically based on account region
		phoneToCheck := recipient.User
		// Strip Indonesian country code (62) if present to avoid double 62
		if strings.HasPrefix(phoneToCheck, "62") && len(phoneToCheck) > 2 {
			phoneToCheck = phoneToCheck[2:]
		}

		fmt.Printf("[SendMedia] IsOnWhatsApp checking: %s (from %s)\n", phoneToCheck, recipient.User)

		// Use 30 second timeout for IsOnWhatsApp check
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		isOnWhatsApp, err := client.IsOnWhatsApp(ctx, []string{phoneToCheck})
		cancel() // Cancel immediately after call

		if err != nil {
			// Log the error but don't fail - try to send anyway
			fmt.Printf("[SendMedia] IsOnWhatsApp check failed for %s: %v (akan tetap coba kirim)\n", phoneToCheck, err)
		} else if len(isOnWhatsApp) > 0 {
			fmt.Printf("[SendMedia] IsOnWhatsApp result for %s: IsIn=%v, JID=%s\n",
				phoneToCheck, isOnWhatsApp[0].IsIn, isOnWhatsApp[0].JID.String())
			if !isOnWhatsApp[0].IsIn {
				return "", ErrUserNotRegistered
			}
		} else {
			fmt.Printf("[SendMedia] IsOnWhatsApp returned empty result for %s (akan tetap coba kirim)\n", phoneToCheck)
		}
	}

	// Use pooled HTTP client
	resp, err := s.httpClient.Get().Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to download media: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read media body: %w", err)
	}

	mimeType := http.DetectContentType(data)
	if resp.Header.Get("Content-Type") != "" && resp.Header.Get("Content-Type") != "application/octet-stream" {
		mimeType = resp.Header.Get("Content-Type")
	}

	var msg *waE2E.Message

	if strings.HasPrefix(mimeType, "image/") {
		uploaded, err := client.Upload(context.Background(), data, whatsmeow.MediaImage)
		if err != nil {
			return "", fmt.Errorf("failed to upload image: %w", err)
		}

		msg = &waE2E.Message{
			ImageMessage: &waE2E.ImageMessage{
				Caption:       proto.String(caption),
				Mimetype:      proto.String(mimeType),
				URL:           proto.String(uploaded.URL),
				DirectPath:    proto.String(uploaded.DirectPath),
				MediaKey:      uploaded.MediaKey,
				FileEncSHA256: uploaded.FileEncSHA256,
				FileSHA256:    uploaded.FileSHA256,
				FileLength:    proto.Uint64(uint64(len(data))),
			},
		}
	} else {
		uploaded, err := client.Upload(context.Background(), data, whatsmeow.MediaDocument)
		if err != nil {
			return "", fmt.Errorf("failed to upload document: %w", err)
		}

		if fileName == "" {
			fileName = "file"
		}

		msg = &waE2E.Message{
			DocumentMessage: &waE2E.DocumentMessage{
				Caption:       proto.String(caption),
				Mimetype:      proto.String(mimeType),
				FileName:      proto.String(fileName),
				URL:           proto.String(uploaded.URL),
				DirectPath:    proto.String(uploaded.DirectPath),
				MediaKey:      uploaded.MediaKey,
				FileEncSHA256: uploaded.FileEncSHA256,
				FileSHA256:    uploaded.FileSHA256,
				FileLength:    proto.Uint64(uint64(len(data))),
			},
		}
	}

	sendResp, err := client.SendMessage(context.Background(), recipient, msg)
	if err != nil {
		return "", err
	}
	return sendResp.ID, nil
}

// GetClientCount returns the number of connected clients (for monitoring)
func (s *Service) GetClientCount() int {
	return s.clientPool.Count()
}
