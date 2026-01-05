package whatsapp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
	Clients          map[string]*whatsmeow.Client
	RejectionConfigs map[string]RejectionConfig
	QRCodes          map[string]string
	Store            *store.Store
	WebhookURL       string
}

type RejectionConfig struct {
	RejectCall         string   `json:"reject_call"`          // "Y" or "N"
	RejectExcludePhone []string `json:"reject_exclude_phone"` // List of JIDs or phones
	RejectMessage      string   `json:"reject_message"`
}

func NewService(s *store.Store, webhookURL string) *Service {
	return &Service{
		Store:            s,
		Clients:          make(map[string]*whatsmeow.Client),
		RejectionConfigs: make(map[string]RejectionConfig),
		QRCodes:          make(map[string]string),
		WebhookURL:       webhookURL,
	}
}

func (s *Service) GetClient(token string) (*whatsmeow.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if client, ok := s.Clients[token]; ok {
		return client, nil
	}

	device, err := s.Store.GetDevice(token)
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	// Create client
	client := whatsmeow.NewClient(device, nil) // Logging nil for now
	s.Clients[token] = client

	// Add event handler
	client.AddEventHandler(func(evt interface{}) {
		// Handle internal events like PairSuccess
		switch v := evt.(type) {
		case *events.PairSuccess:
			fmt.Printf("Token %s paired successfully with JID %s\n", token, v.ID)
			// Try to get push name if available, otherwise empty
			pushName := ""
			if client.Store.PushName != "" {
				pushName = client.Store.PushName
			}
			s.Store.UpdateTokenJID(token, v.ID, pushName)
		case *events.CallOffer:
			s.handleCallRejection(token, v, client)
		case *events.PushName:
			// Update push name if it changes AND it matches our JID
			if client.Store.ID != nil && v.JID.User == client.Store.ID.User {
				if v.Message != nil && v.OldPushName != v.NewPushName {
					s.Store.UpdateTokenJID(token, *client.Store.ID, v.NewPushName)
				}
			}
		case *events.Connected:
			// Saat terhubung, sinkronkan nama ke database
			// Jalankan dalam goroutine dengan delay untuk menunggu PushName tersedia
			go func() {
				// Tunggu sebentar agar PushName tersedia
				time.Sleep(2 * time.Second)

				if client.Store.ID == nil {
					return
				}

				pushName := client.Store.PushName
				phoneNumber := client.Store.ID.User

				// Jika PushName kosong, gunakan nomor sebagai fallback
				if pushName == "" {
					pushName = phoneNumber
				}

				// Jika PushName sama dengan nomor telepon, cek dulu nama di database
				if pushName == phoneNumber {
					// Cek apakah sudah ada nama di database
					dbInfo, err := s.Store.GetDeviceInfo(token)
					if err == nil && dbInfo != nil && dbInfo.Name != "" && dbInfo.Name != phoneNumber {
						// Gunakan nama dari database, jangan timpa dengan nomor telepon
						fmt.Printf("Token %s: Connected - nama sudah ada di DB: %s, skip update\n", token, dbInfo.Name)
						return
					}
				}

				// Update dengan PushName yang valid
				s.Store.UpdateTokenJID(token, *client.Store.ID, pushName)
				fmt.Printf("Token %s: Connected - nama disinkronkan ke database: %s\n", token, pushName)
			}()
		case *events.Message:
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
				workspace := "default" // Or fetch from store
				// Get workspace from store
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
		}

	})

	return client, nil
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
			// Hapus QR dari cache karena sudah tidak diperlukan
			s.mu.Lock()
			delete(s.QRCodes, token)
			s.mu.Unlock()
			return
		} else {
			fmt.Printf("Token %s: QR event: %s\n", token, evt.Event)
		}
	}

	// Channel ditutup (timeout atau error)
	// Bersihkan cache QR
	s.mu.Lock()
	delete(s.QRCodes, token)
	s.mu.Unlock()
	fmt.Printf("Token %s: QR channel ditutup, cache dibersihkan\n", token)

	// Disconnect session jika belum login (tidak terpakai)
	s.mu.RLock()
	client, ok := s.Clients[token]
	s.mu.RUnlock()

	if ok && client != nil && client.Store.ID == nil {
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

	// Force reconnect if stuck in connected but not logged in state
	if client.IsConnected() && client.Store.ID == nil {
		fmt.Printf("Token %s stuck (connected=true, loggedin=false). Force reconnecting...\n", token)
		client.Disconnect()
	}

	if !client.IsConnected() {
		// Ensure QR channel is initialized before connecting
		// valid for 60s
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
			return // Excluded
		}
	}

	// Reject Call
	err := client.RejectCall(context.Background(), evt.CallCreator, evt.CallID)
	if err != nil {
		fmt.Printf("Failed to reject call from %s: %v\n", caller, err)
	} else {
		fmt.Printf("Rejected call from %s\n", caller)
	}

	// Send Message
	if config.RejectMessage != "" {
		s.SendMessage(token, evt.CallCreator.String(), config.RejectMessage)
	}
}

func (s *Service) DeleteClient(token string) error {
	s.mu.Lock()
	client, ok := s.Clients[token]
	if ok {
		if client.IsConnected() {
			// Try to logout
			_ = client.Logout(context.Background())
		}
		client.Disconnect()
		delete(s.Clients, token)
	}
	s.mu.Unlock()

	return s.Store.DeleteDevice(token)
}

func (s *Service) handleWebhookEvent(token string, evt interface{}) {
	// 1. Check for per-token webhook
	webhookURL, err := s.Store.GetWebhook(token)
	if err != nil || webhookURL == "" {
		// Fallback to global webhook
		webhookURL = s.WebhookURL
	}

	if webhookURL == "" {
		return
	}

	var eventType string
	var eventData interface{}

	switch v := evt.(type) {
	case *events.Message:
		eventType = "message"
		eventData = map[string]interface{}{
			"id":        v.Info.ID,
			"chat":      v.Info.Chat.String(),
			"sender":    v.Info.Sender.String(),
			"timestamp": v.Info.Timestamp.Unix(),
			"message":   v.Message,
			"push_name": v.Info.PushName,
		}
	case *events.Receipt:
		eventType = "receipt"
		eventData = map[string]interface{}{
			"chat":        v.Chat.String(),
			"sender":      v.Sender.String(),
			"timestamp":   v.Timestamp.Unix(),
			"type":        v.Type, // Read, Delivered, etc.
			"message_ids": v.MessageIDs,
		}
	default:
		return // Ignore other events for now
	}

	payload := map[string]interface{}{
		"token": token,
		"event": eventType,
		"data":  eventData,
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Failed to marshal webhook payload: %v\n", err)
		return
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		fmt.Printf("Failed to send webhook to %s: %v\n", webhookURL, err)
		return
	}
	defer resp.Body.Close()
}

// GetQR returns a QR code PNG bytes for the given token
func (s *Service) Login(token string) ([]byte, error) {
	client, err := s.GetClient(token)
	if err != nil {
		return nil, err
	}

	if client.Store.ID != nil {
		// Already logged in
		return nil, fmt.Errorf("already logged in as %s", client.Store.ID)
	}

	// Cek cache QR
	s.mu.RLock()
	code, ok := s.QRCodes[token]
	s.mu.RUnlock()

	if ok && code != "" {
		// Generate PNG dari kode QR yang di-cache
		png, err := qrcode.Encode(code, qrcode.Medium, 256)
		return png, err
	}

	// Jika tidak ada kode di cache, cek status koneksi
	if client.IsConnected() {
		return nil, fmt.Errorf("waiting_for_qr")
	}

	// Jika tidak terhubung dan tidak ada kode, mungkin StartSession belum dipanggil
	return nil, fmt.Errorf("not_connected")
}

var ErrQRTimeout = fmt.Errorf("qr_timeout")

// LoginStream streams QR codes to the provided channel until timeout or explicit context cancellation.
// It enforces a 60s timeout for the session if not logged in.
func (s *Service) LoginStream(ctx context.Context, token string, qrStream chan<- string) error {
	client, err := s.GetClient(token)
	if err != nil {
		return err
	}

	if client.Store.ID != nil {
		return fmt.Errorf("already_logged_in")
	}

	// Ensure session is started and consumer is running
	// Call StartSession if:
	// 1. Not connected at all, OR
	// 2. Connected but not logged in (stuck state that needs reconnect)
	if !client.IsConnected() || (client.IsConnected() && client.Store.ID == nil) {
		// Use empty rejection config as default for auto-start
		// In a real app we might want to fetch existing config
		err := s.StartSession(token, RejectionConfig{})
		if err != nil {
			return err
		}
	}

	// 60 Second Session Timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var lastCode string

	// Poll for QR updates
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if logged in (success)
			if client.Store.ID != nil {
				return nil
			}

			// Check if disconnected unexpectedly (maybe restart?)
			if !client.IsConnected() {
				// Try to restart? or fail?
				// Let's fail so frontend retries
				return fmt.Errorf("disconnected")
			}

			// Read Cache
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

func (s *Service) SendMessage(token, to, text string) (string, error) {
	client, err := s.GetClient(token)
	if err != nil {
		return "", err
	}

	if !client.IsConnected() {
		return "", fmt.Errorf("client not logged in")
	}

	// Parse JID
	if !strings.Contains(to, "@") {
		to = to + "@s.whatsapp.net"
	}
	recipient, err := types.ParseJID(to)
	if err != nil {
		return "", fmt.Errorf("invalid recipient JID: %w", err)
	}

	// Check if registered (skip for groups)
	if recipient.Server != "g.us" {
		isOnWhatsApp, err := client.IsOnWhatsApp(context.Background(), []string{recipient.User})
		if err != nil {
			return "", fmt.Errorf("failed to check if on whatsapp: %w", err)
		}
		if len(isOnWhatsApp) == 0 || !isOnWhatsApp[0].IsIn {
			return "", ErrUserNotRegistered
		}
	}

	msg := &waE2E.Message{
		Conversation: proto.String(text),
	}

	resp, err := client.SendMessage(context.Background(), recipient, msg)
	if err != nil {
		return "", err
	}
	return resp.ID, nil
}

// PairPhone initiates pairing via phone number and returns the code
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

	// Wait for connection to be ready before requesting code?
	// Usually PairPhone handles it or needs connection.

	// Type of pairing: 2 = Phone number pairing
	browserName := os.Getenv("WHATSAPP_BROWSER")
	if browserName == "" {
		browserName = "Google Chrome"
	}
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

	// Check for nil contacts structure
	if client.Store == nil || client.Store.Contacts == nil {
		return nil, fmt.Errorf("contacts store not initialized")
	}

	// Ensure contacts are loaded? They are loaded on connect usually.
	// But we can check store directly.
	return client.Store.Contacts.GetAllContacts(context.Background())
}

func (s *Service) GetGroups(token string) ([]*types.GroupInfo, error) {
	client, err := s.GetClient(token)
	if err != nil {
		return nil, err
	}

	if !client.IsConnected() {
		// Try to connect logic or check if loaded
		if client.Store.ID != nil {
			client.Connect()
			time.Sleep(1 * time.Second) // Wait brief moment
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

	// Attempt to connect if not connected, to ensure we have latest state?
	// Or just check store.
	if !client.IsConnected() {
		if client.Store.ID != nil {
			// If we have an ID, we are effectively "logged in" but disconnected.
			// We can try to connect in background?
			go client.Connect()
			time.Sleep(500 * time.Millisecond) // Give it a moment?
		}
	}

	// Try to get info from local DB first for consistency
	dbInfo, _ := s.Store.GetDeviceInfo(token)

	status := &SessionStatus{
		IsLoggedIn: client.Store.ID != nil,
	}

	if dbInfo != nil {
		status.Name = dbInfo.Name // Prefer DB name
	}

	if client.Store.ID != nil {
		status.JID = client.Store.ID.String()
		status.Phone = client.Store.ID.User
		if status.Name == "" {
			status.Name = client.Store.PushName
		}

		// Fallback: Jika nama di database kosong tapi client punya PushName, sync ke database
		if (dbInfo == nil || dbInfo.Name == "") && client.Store.PushName != "" && client.Store.PushName != client.Store.ID.User {
			go s.Store.UpdateTokenJID(token, *client.Store.ID, client.Store.PushName)
			fmt.Printf("Token %s: GetStatus - sinkronkan nama ke database: %s\n", token, client.Store.PushName)
		}

		// Try to get profile picture
		// We use a short timeout context to avoid blocking too long
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Get profile picture using Non-AD JID (User JID)
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

	// Logout from WhatsApp (this deletes the session from the store)
	if err := client.Logout(context.Background()); err != nil {
		return fmt.Errorf("failed to logout: %w", err)
	}

	// Clear JID dan nama dari database supaya dashboard menampilkan status yang benar
	s.Store.ClearTokenJID(token)

	// Hapus client dari cache agar state bersih
	s.mu.Lock()
	delete(s.Clients, token)
	delete(s.QRCodes, token)
	s.mu.Unlock()

	return nil
}

func (s *Service) Reconnect(token string) error {
	client, err := s.GetClient(token)
	if err != nil {
		return err
	}

	// Disconnect if connected
	if client.IsConnected() {
		client.Disconnect()
	}

	// Wait a bit?
	time.Sleep(500 * time.Millisecond)

	// Connect again
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

	recipient, err := types.ParseJID(to)
	if err != nil {
		return "", fmt.Errorf("invalid recipient JID: %w", err)
	}

	// Check if registered (skip for groups)
	if recipient.Server != "g.us" {
		isOnWhatsApp, err := client.IsOnWhatsApp(context.Background(), []string{recipient.User})
		if err != nil {
			return "", fmt.Errorf("failed to check if on whatsapp: %w", err)
		}
		if len(isOnWhatsApp) == 0 || !isOnWhatsApp[0].IsIn {
			return "", ErrUserNotRegistered
		}
	}

	// Download file
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to download media: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read media body: %w", err)
	}

	// Detect content type
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
		// Document
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
