package whatsapp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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

	"image"
	"image/jpeg"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/nfnt/resize"

	// "golang.org/x/image/webp" // Standard image library doesn't support webp decoding easily without external lib, sticking to png/jpg for now or just generic decode
	_ "image/gif"
)

type Service struct {
	mu               sync.RWMutex
	clientPool       *ClientPool
	RejectionConfigs map[string]RejectionConfig
	QRCodes          map[string]string
	Store            *store.Store
	WebhookURL       string
	WebhookType      string // "in" or "all"
	SaveMedia        string // "NULL", "LOCAL", "S3"
	S3Client         *minio.Client
	S3Bucket         string
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

	wt := os.Getenv("WEBHOOKTYPE")
	saveMedia := strings.ToUpper(os.Getenv("SAVE_MEDIA"))
	if saveMedia == "TRUE" {
		saveMedia = "LOCAL"
	} else if saveMedia == "FALSE" || saveMedia == "" {
		saveMedia = "NULL"
	}

	var s3Client *minio.Client
	var s3Bucket string

	if saveMedia == "S3" {
		endpoint := os.Getenv("S3_ENDPOINT")
		accessKeyID := os.Getenv("S3_ACCESS_KEY")
		secretAccessKey := os.Getenv("S3_SECRET_KEY")
		s3Bucket = os.Getenv("S3_BUCKET")
		useSSL := os.Getenv("S3_USE_SSL") == "true"
		region := os.Getenv("S3_REGION")

		var err error
		s3Client, err = minio.New(endpoint, &minio.Options{
			Creds:  credentials.NewStaticV4(accessKeyID, secretAccessKey, ""),
			Secure: useSSL,
			Region: region,
		})
		if err != nil {
			fmt.Printf("[NewService] Failed to initialize S3 client: %v. Fallback to NULL.\n", err)
			saveMedia = "NULL"
		} else {
			fmt.Println("[NewService] S3 Client initialized successfully")
		}
	}

	fmt.Printf("[NewService] WebhookURL: %s, WebhookType: %s, SaveMedia: %s\n", webhookURL, wt, saveMedia)

	return &Service{
		Store:            s,
		clientPool:       NewClientPool(poolCfg),
		RejectionConfigs: make(map[string]RejectionConfig),
		QRCodes:          make(map[string]string),
		WebhookURL:       webhookURL,
		WebhookType:      wt,
		SaveMedia:        saveMedia,
		S3Client:         s3Client,
		S3Bucket:         s3Bucket,
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
				
				// Cleanup old status analytics data (keep for 7 days)
				if err := s.Store.Driver.CleanupOldStatuses(7); err != nil {
					fmt.Printf("[PeriodicCheck] Failed to cleanup old statuses: %v\n", err)
				}
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
		} else {
			// Active Health Check (Ping)
			// Send a presence update to check if connection is really alive
			// Use a short timeout to detect "frozen" connections quickly
			// ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			// err := client.SendPresence(types.PresenceAvailable) // SendPresence is often asynchronous in some libs, but usually sends data
			// In whatsmeow, SendPresence writes to socket. If socket is dead/full, it might block or error.

			// Note: client.SendPresence doesn't take context in older versions? Checking signature...
			// It seems whatsmeow SendPresence sends a stanza.

			// Let's use a goroutine with timeout to ensure we don't block the loop if SendPresence hangs
			pingErrChan := make(chan error, 1)
			go func() {
				pingErrChan <- client.SendPresence(context.Background(), types.PresenceAvailable)
			}()

			select {
			case err := <-pingErrChan:
				if err != nil {
					fmt.Printf("[PeriodicCheck] Active ping failed for %s: %v. Force reconnecting...\n", token, err)
					client.Disconnect()
					time.Sleep(1 * time.Second)
					if err := client.Connect(); err != nil {
						fmt.Printf("[PeriodicCheck] Failed to force reconnect %s: %v\n", token, err)
					} else {
						fmt.Printf("[PeriodicCheck] Successfully force reconnected %s\n", token)
					}
				} else {
					// Ping success, connection is alive
					// fmt.Printf("[PeriodicCheck] Active ping success for %s\n", token)
				}
			case <-time.After(10 * time.Second):
				fmt.Printf("[PeriodicCheck] Active ping timed out for %s. Connection likely frozen. Force reconnecting...\n", token)
				client.Disconnect() // This might block if lock is held? whatsmeow Connect/Disconnect should be safe
				time.Sleep(1 * time.Second)
				if err := client.Connect(); err != nil {
					fmt.Printf("[PeriodicCheck] Failed to force reconnect %s: %v\n", token, err)
				} else {
					fmt.Printf("[PeriodicCheck] Successfully force reconnected %s\n", token)
				}
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

// cleanupSession performs full session cleanup for a token.
// This purges whatsmeow session data, clears DB, removes from pool, and cleans QR cache.
// Call this whenever a device is no longer usable and needs a fresh QR scan.
func (s *Service) cleanupSession(token string, reason string) {
	fmt.Printf("[CleanupSession] Token %s - Reason: %s. Purging session data...\n", token, reason)

	// Step 1: Purge whatsmeow session data (encryption keys, identity, etc.)
	s.Store.PurgeDeviceSession(token)

	// Step 2: Clear JID/name in account_tokens (keep the token row)
	s.Store.ClearTokenJID(token)

	// Step 3: Remove client from pool (disconnects if still connected)
	s.clientPool.Remove(token)

	// Step 4: Clean up QR cache
	s.mu.Lock()
	delete(s.QRCodes, token)
	s.mu.Unlock()

	fmt.Printf("[CleanupSession] Token %s fully cleaned up. Ready for fresh QR scan.\n", token)
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

	case *events.Receipt:
		s.workerPool.Submit(func() {
			// DEBUG: Print all receipts to see what a view looks like
			fmt.Printf("[DEBUG-RECEIPT] Type=%s, Chat=%s, Sender=%s, MsgIDs=%v\n", v.Type, v.Chat.String(), v.Sender.String(), v.MessageIDs)

			// Track Status View: If it's a read receipt for a broadcast, it's someone viewing our status
			if v.Chat.Server == "broadcast" && (string(v.Type) == "read" || string(v.Type) == "read-self" || string(v.Type) == "played") {
				for _, msgID := range v.MessageIDs {
					_ = s.Store.Driver.AddStatusView(string(msgID), v.Sender.ToNonAD().String())
				}
			}

			s.handleWebhookEvent(token, v)
		})

	case *events.LoggedOut:
		s.workerPool.Submit(func() {
			reason := fmt.Sprintf("LoggedOut event (reason: %d)", v.Reason)
			s.cleanupSession(token, reason)
		})

	case *events.TemporaryBan:
		s.workerPool.Submit(func() {
			reason := fmt.Sprintf("TemporaryBan (code: %v, expire: %v)", v.Code, v.Expire)
			fmt.Printf("[Event] Token %s: %s\n", token, reason)
			// Temporary ban means the session is unusable.
			// Purge everything so user can re-scan with a fresh session after ban expires.
			s.cleanupSession(token, reason)
		})

	case *events.StreamError:
		s.workerPool.Submit(func() {
			reason := fmt.Sprintf("StreamError (code: %s)", v.Code)
			fmt.Printf("[Event] Token %s: %s\n", token, reason)
			// Stream errors indicate the session is broken.
			// Clean up so the device can be re-scanned.
			s.cleanupSession(token, reason)
		})

	case *events.ClientOutdated:
		s.workerPool.Submit(func() {
			reason := "ClientOutdated - WhatsApp server rejected connection, client version too old"
			fmt.Printf("[Event] Token %s: %s\n", token, reason)
			s.cleanupSession(token, reason)
		})

	case *events.Disconnected:
		s.workerPool.Submit(func() {
			fmt.Printf("[Event] Token %s: Disconnected from WhatsApp\n", token)
			// Don't purge session for normal disconnects (network issues, etc.)
			// The periodic check will handle reconnection.
			// But if the device no longer has a valid session, clean up the DB status.
			if client.Store.ID == nil {
				fmt.Printf("[Event] Token %s: Disconnected with no valid session. Cleaning up.\n", token)
				s.Store.ClearTokenJID(token)
			}
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
		// Track Outgoing Status: If this is a status we posted (even from the phone itself)
		if v.Info.Chat.Server == "broadcast" {
			_ = s.Store.Driver.InsertStatusMessage(token, v.Info.ID)
		}

		// If FromMe, check if we want to send webhook (omnichannel)
		fmt.Printf("[handleMessage] Outgoing message detected. WebhookType: %s\n", s.WebhookType)
		if s.WebhookType == "all" {
			fmt.Println("[handleMessage] Sending outgoing webhook event...")
			s.handleWebhookEvent(token, v)
		}
		return
	}

	// Track Status Reply: If this is a reply (has context info), attempt to record it as a status reply
	if ext := v.Message.GetExtendedTextMessage(); ext != nil && ext.GetContextInfo() != nil {
		stanzaId := ext.GetContextInfo().GetStanzaID()
		if stanzaId != "" {
			// It's a reply to some message. If it's our status, this will be recorded.
			_ = s.Store.Driver.AddStatusReply(stanzaId, v.Info.Sender.ToNonAD().String())
		}
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

	// Filter status broadcasts
	if evtV, ok := evt.(*events.Message); ok {
		if evtV.Info.Chat.String() == "status@broadcast" {
			return
		}
	}

	var payload map[string]interface{}

	switch v := evt.(type) {
	case *events.Message:
		// Handle LID (Privacy ID) resolution
		senderJID := v.Info.Sender
		if senderJID.Server == "lid" {
			// Get client to access store
			client, _ := s.GetClient(token)
			if client != nil && client.Store.LIDs != nil {
				pnJID, err := client.Store.LIDs.GetPNForLID(context.Background(), senderJID)
				if err == nil && !pnJID.IsEmpty() {
					fmt.Printf("[Webhook] Resolved LID %s to Phone %s\n", senderJID, pnJID)
					senderJID = pnJID
				} else {
					fmt.Printf("[Webhook] Failed to resolve LID %s: %v\n", senderJID, err)
				}
			}
		}

		// Get phone number from sender (remove @s.whatsapp.net suffix)
		phone := senderJID.User

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
			"payload":   string(messagesJSON),
			"type":      msgType,
			"update_at": time.Now().Format("2006-01-02 15:04:05"),
			"message":   msgText,
		}

		// Process Media if exists
		// Get client for download
		client, _ := s.GetClient(token)
		if client != nil {
			mediaURL, err := s.processMedia(token, client, v)
			if err != nil {
				fmt.Printf("[Webhook] Failed to process media: %v\n", err)
			}
			if mediaURL != "" {
				payload["media_url"] = mediaURL
			}
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

	// Use pooled HTTP client with retry logic
	maxRetries := 3
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		// Create buffer for this attempt
		bodyBuffer := bytes.NewBuffer(jsonBody)

		resp, err := s.httpClient.Get().Post(webhookURL, "application/json", bodyBuffer)
		if err != nil {
			lastErr = err
			fmt.Printf("Attempt %d/%d: Failed to send webhook to %s: %v\n", i+1, maxRetries, webhookURL, err)

			// Wait before retry (exponential backoff: 1s, 2s, 4s...)
			if i < maxRetries-1 {
				time.Sleep(time.Duration(1<<i) * time.Second)
			}
			continue
		}
		resp.Body.Close()

		// Success
		if i > 0 {
			fmt.Printf("Successfully sent webhook to %s after %d retries\n", webhookURL, i)
		}
		return
	}

	fmt.Printf("Given up sending webhook to %s after %d attempts. Last error: %v\n", webhookURL, maxRetries, lastErr)
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

	// Handle case where someone put 00 prefix for international (e.g., 0041)
	if strings.HasPrefix(phone, "00") && len(phone) > 2 {
		phone = phone[2:]
	}

	// Convert 08 prefix to 628 (Indonesian format)
	if strings.HasPrefix(phone, "08") {
		phone = "62" + phone[1:]
	}

	// Handle case where someone put 0628 or similar (after removing +)
	// But only if it's not a valid 0-prefixed international number (which we can't be sure about,
	// but usually leading 0 followed by digits is a local number format)
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

		if normalized == "" {
			return "", fmt.Errorf("phone number is empty or invalid")
		}

		if len(normalized) < 5 {
			return "", fmt.Errorf("phone number too short (minimum 5 digits)")
		}

		fmt.Print("Gooooo=>>>")
		to = normalized + "@s.whatsapp.net"
	}
	recipient, err := types.ParseJID(to)
	if err != nil {
		return "", fmt.Errorf("invalid recipient JID: %w", err)
	}

	// Check if registered on WhatsApp (skip for groups and broadcast)
	// Can be disabled with SKIP_ISONWHATSAPP=true in .env
	skipCheck := os.Getenv("SKIP_ISONWHATSAPP") == "true"
	if recipient.Server != "g.us" && recipient.Server != "broadcast" && !skipCheck {
		// For IsOnWhatsApp, we need to send number WITHOUT country code
		// if it matches the sender's country code to avoid doubling.
		phoneToCheck := recipient.User

		// Get sender country code (simple heuristic for Indonesia)
		senderJID := client.Store.ID
		senderCC := "62" // default
		if senderJID != nil {
			if !strings.HasPrefix(senderJID.User, "62") && len(senderJID.User) >= 2 {
				// If sender is not Indonesian, maybe it's another country
				// We can try to guess or just use 62 as a safe default for Indonesian users
				// For now, let's see if sender starts with 62
			}
			if senderJID != nil && strings.HasPrefix(senderJID.User, "62") {
				senderCC = "62"
			} else if senderJID != nil && len(senderJID.User) >= 2 {
				// Generic sender CC detection (first 2 digits)
				senderCC = senderJID.User[:2]
			}
		}

		// Only trim CC if it matches the sender's CC
		if strings.HasPrefix(phoneToCheck, senderCC) && len(phoneToCheck) <= 13 {
			phoneToCheck = strings.TrimPrefix(phoneToCheck, senderCC)
		}

		fmt.Printf("[SendMessage] >==> IsOnWhatsApp checking: %s (original: %s, senderCC: %s)\n", phoneToCheck, recipient.User, senderCC)

		// Use 30 second timeout for IsOnWhatsApp check
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		isOnWhatsApp, err := client.IsOnWhatsApp(ctx, []string{phoneToCheck})
		cancel() // Cancel immediately after call

		if err != nil {
			// Log the error but don't fail - try to send anyway
			fmt.Printf("[SendMessage] IsOnWhatsApp check failed for %s: %v (akan tetap coba kirim)\n", phoneToCheck, err)
		} else if len(isOnWhatsApp) > 0 {
			result := isOnWhatsApp[0]
			fmt.Printf("[SendMessage] IsOnWhatsApp result for %s: IsIn=%v, JID=%s\n",
				phoneToCheck, result.IsIn, result.JID.String())

			if !result.IsIn {
				// HEURISTIC: If result is False but the returned JID starts with double country code
				// (e.g. 6241...), it's a false negative due to server mangling.
				if senderCC != "" && strings.HasPrefix(result.JID.User, senderCC) && !strings.HasPrefix(recipient.User, senderCC) {
					fmt.Printf("[SendMessage] Detected false negative for international number (mangled JID: %s). Proceeding anyway.\n", result.JID.String())
				} else {
					return "", ErrUserNotRegistered
				}
			} else {
				// Update recipient to the true JID returned by WhatsApp
				// This prevents 400 errors for numbers that have different canonical forms
				// (e.g. Brazil's 9 digit or Mexico's 1 prefix)
				recipient = result.JID
			}
		} else {
			fmt.Printf("[SendMessage] IsOnWhatsApp returned empty result for %s (treating as not registered)\n", phoneToCheck)
			return "", ErrUserNotRegistered
		}
	}

	msg := &waE2E.Message{
		Conversation: proto.String(text),
	}

	if recipient.Server == "broadcast" {
		// Text statuses require ExtendedTextMessage and a background color
		msg = &waE2E.Message{
			ExtendedTextMessage: &waE2E.ExtendedTextMessage{
				Text:           proto.String(text),
				BackgroundArgb: proto.Uint32(0xFF25D366), // Default WhatsApp Green background
			},
		}
	}

	// Send with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.SendMessage(ctx, recipient, msg)
	if err != nil {
		errStr := strings.ToLower(err.Error())

		// Auto-reconnect on 400 error logic
		if strings.Contains(errStr, "server returned error 400") || strings.Contains(errStr, "bad request") {
			fmt.Printf("[SendMessage] Received 400 error for token %s. Attempting 1x auto-reconnect...\n", token)
			client.Disconnect()
			time.Sleep(1 * time.Second)
			
			if reconnectErr := client.Connect(); reconnectErr == nil {
				// Retry sending
				fmt.Printf("[SendMessage] Reconnect success, retrying send for token %s...\n", token)
				
				// Recreate context for retry
				retryCtx, retryCancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer retryCancel()
				
				resp, err = client.SendMessage(retryCtx, recipient, msg)
				if err != nil {
					retryErrStr := strings.ToLower(err.Error())
					if strings.Contains(retryErrStr, "server returned error 400") || strings.Contains(retryErrStr, "bad request") {
						fmt.Printf("[SendMessage] Send failed again with 400 after reconnect. Purging session for %s...\n", token)
						// Run cleanup in goroutine to avoid blocking
						go s.cleanupSession(token, "Persistent Error 400 on send")
						return "", err
					}
				}
			} else {
				fmt.Printf("[SendMessage] Reconnect failed for %s: %v. Purging session...\n", token, reconnectErr)
				go s.cleanupSession(token, "Failed to reconnect after 400 error")
				return "", err
			}
		}

		if err != nil {
			fmt.Printf("\n[DEBUG-SEND] SendMessage failed for %s!\n", recipient.String())
			fmt.Printf("[DEBUG-SEND] Raw Error: %+v\n", err)
			fmt.Printf("[DEBUG-SEND] Error Type: %T\n\n", err)

			errStr = strings.ToLower(err.Error())
			// Check if it's a "not registered" error from WhatsApp
			if strings.Contains(errStr, "not on whatsapp") || strings.Contains(errStr, "unknown user") || strings.Contains(errStr, "recipient not found") {
				return "", ErrUserNotRegistered
			}
			return "", err
		}
	}

	// Record Status Message in DB for Analytics
	if err == nil && recipient.Server == "broadcast" {
		_ = s.Store.Driver.InsertStatusMessage(token, resp.ID)
	}

	fmt.Printf("[SendMessage] Success. ID: %s\n", resp.ID)
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

	// Browser name moved to beginning of function

	// Browser name
	browserName := os.Getenv("DEVICE_NAME")
	if browserName == "" {
		browserName = "Chrome"
	}

	phone = NormalizePhone(phone)

	// WhatsApp requires a specific format for the client display name in PairPhone (e.g. "Browser (OS)").
	// Using a known format like "Chrome (Windows)" avoids the 400 bad-request error.
	clientDisplayName := "Chrome (Windows)"
	if browserName != "Chrome" && browserName != "" {
		clientDisplayName = browserName + " (Windows)"
	}

	fmt.Printf("[PairPhone] Phone: %s, Browser: %s\n", phone, clientDisplayName)

	code, err := client.PairPhone(context.Background(), phone, true, whatsmeow.PairClientChrome, clientDisplayName)
	if err != nil {
		return "", err
	}

	return code, nil
}

// processMedia downloads and saves media based on SAVE_MEDIA config
func (s *Service) processMedia(token string, client *whatsmeow.Client, evt *events.Message) (string, error) {
	if s.SaveMedia == "NULL" {
		return "", nil
	}

	var data []byte
	var err error
	var ext string
	var mimeType string

	msg := evt.Message

	if img := msg.GetImageMessage(); img != nil {
		data, err = client.Download(context.Background(), img)
		ext = "jpg"
		mimeType = "image/jpeg"

		// Compress Image
		if len(data) > 100*1024 { // Only compress if > 100KB
			compressedData, errCompress := s.compressImage(data)
			if errCompress == nil {
				data = compressedData
				fmt.Printf("[processMedia] Image compressed. Size: %d bytes\n", len(data))
			} else {
				fmt.Printf("[processMedia] Failed to compress image: %v\n", errCompress)
			}
		}
	} else if vid := msg.GetVideoMessage(); vid != nil {
		data, err = client.Download(context.Background(), vid)
		ext = "mp4"
		mimeType = "video/mp4"
	} else if aud := msg.GetAudioMessage(); aud != nil {
		data, err = client.Download(context.Background(), aud)
		ext = "ogg"
		mimeType = "audio/ogg"
	} else if doc := msg.GetDocumentMessage(); doc != nil {
		data, err = client.Download(context.Background(), doc)
		ext = "" // Use filename extension if possible
		mimeType = doc.GetMimetype()

		// Try to get extension from filename
		if doc.FileName != nil {
			parts := strings.Split(*doc.FileName, ".")
			if len(parts) > 1 {
				ext = parts[len(parts)-1]
			}
		}
		if ext == "" {
			// Fallback: simple mapping
			switch mimeType {
			case "application/pdf":
				ext = "pdf"
			case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
				ext = "xlsx"
			case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
				ext = "docx"
			}
		}

	} else if stk := msg.GetStickerMessage(); stk != nil {
		data, err = client.Download(context.Background(), stk)
		ext = "webp"
		mimeType = "image/webp"
	} else {
		return "", nil
	}

	if err != nil {
		return "", fmt.Errorf("failed to download media: %w", err)
	}

	if ext == "" {
		ext = "bin"
	}

	fileName := fmt.Sprintf("%s.%s", evt.Info.ID, ext)

	// Create current date folder: YYYY-MM-DD
	currentDate := time.Now().Format("2006-01-02")

	if s.SaveMedia == "LOCAL" {
		// Folder structure: media/{token}/{date}/
		dirPath := filepath.Join("media", token, currentDate)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return "", fmt.Errorf("failed to create directory: %w", err)
		}

		filePath := filepath.Join(dirPath, fileName)
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			return "", fmt.Errorf("failed to write file: %w", err)
		}

		// Return full URL
		// Assuming static file server maps /media to ./media
		// URL format: {APP_URL}/media/{token}/{date}/{filename}

		baseURL := os.Getenv("APP_URL")
		if baseURL == "" {
			baseURL = "http://localhost:8080"
		}

		// Remove trailing slash if present
		baseURL = strings.TrimRight(baseURL, "/")

		return fmt.Sprintf("%s/media/%s/%s/%s", baseURL, token, currentDate, fileName), nil
	} else if s.SaveMedia == "S3" {
		if s.S3Client == nil {
			return "", fmt.Errorf("S3 client not initialized")
		}

		objectName := fmt.Sprintf("%s/%s/%s", token, currentDate, fileName)
		reader := bytes.NewReader(data)
		objectSize := int64(len(data))

		_, err := s.S3Client.PutObject(context.Background(), s.S3Bucket, objectName, reader, objectSize, minio.PutObjectOptions{
			ContentType: mimeType,
		})
		if err != nil {
			return "", fmt.Errorf("failed to upload to S3: %w", err)
		}

		// Generate Public URL
		// Assuming public bucket or generate presigned URL
		// For now, let's construct the URL based on endpoint and bucket
		// Format: https://{endpoint}/{bucket}/{objectName} (path style)
		// Or https://{bucket}.{endpoint}/{objectName} (virtual host style)

		// Simple implementation: Use the S3_ENDPOINT as base
		endpoint := os.Getenv("S3_ENDPOINT")
		useSSL := os.Getenv("S3_USE_SSL") == "true"
		protocol := "http"
		if useSSL {
			protocol = "https"
		}

		return fmt.Sprintf("%s://%s/%s/%s", protocol, endpoint, s.S3Bucket, objectName), nil
	}

	return "", nil
}

// compressImage resizes and compresses image to be under 100KB
func (s *Service) compressImage(data []byte) ([]byte, error) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %w", err)
	}

	// Initial quality
	quality := 80
	width := uint(img.Bounds().Dx())

	// Max initial width
	if width > 1280 {
		width = 1280
		img = resize.Resize(width, 0, img, resize.Lanczos3)
	}

	var buf bytes.Buffer
	err = jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality})
	if err != nil {
		return nil, fmt.Errorf("failed to encode initial jpeg: %w", err)
	}

	// Iteratively reduce quality/size until < 100KB or quality too low
	for buf.Len() > 100*1024 && quality > 20 {
		// Reduce quality
		quality -= 10
		if quality < 20 {
			quality = 20
		}

		// If still too big and quality is low, resize
		if quality < 50 && width > 600 {
			width = uint(float64(width) * 0.8)
			img = resize.Resize(width, 0, img, resize.Lanczos3)
		}

		buf.Reset()
		err = jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality})
		if err != nil {
			return nil, fmt.Errorf("failed to re-encode jpeg: %w", err)
		}

		if quality == 20 && buf.Len() > 100*1024 {
			// Cannot compress further effectively
			break
		}
	}

	return buf.Bytes(), nil
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

	// Self-healing: If not logged in (client.Store.ID == nil) but DB has info/JID,
	// it means state is out of sync (e.g. logged out while server was down).
	// We should clear the DB state.
	if client.Store.ID == nil && dbInfo != nil && dbInfo.JID != "" {
		fmt.Printf("Token %s: GetStatus detects stale state (DB has JID but client disconnected). Clearing session.\n", token)
		go s.Store.ClearTokenJID(token)
		// Reset status name in response
		status.Name = ""
		status.JID = ""
		status.Phone = ""
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

	// Try to logout from WhatsApp servers first
	err = client.Logout(context.Background())
	if err != nil {
		// Even if WhatsApp logout fails (e.g. already banned/disconnected),
		// we still want to clean up local session data
		fmt.Printf("[Logout] WhatsApp logout failed for %s: %v. Proceeding with local cleanup.\n", token, err)
	}

	// Full cleanup: purge session, clear DB, remove from pool
	s.cleanupSession(token, "Manual logout")
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

	// Check if registered on WhatsApp (skip for groups and broadcast)
	skipCheck := os.Getenv("SKIP_ISONWHATSAPP") == "true"
	if recipient.Server != "g.us" && recipient.Server != "broadcast" && !skipCheck {
		// For IsOnWhatsApp, we need to send number WITHOUT country code
		// if it matches the sender's country code to avoid doubling.
		phoneToCheck := recipient.User

		// Get sender country code (simple heuristic for Indonesia)
		senderJID := client.Store.ID
		senderCC := "62" // default
		if senderJID != nil {
			if strings.HasPrefix(senderJID.User, "62") {
				senderCC = "62"
			} else if len(senderJID.User) >= 2 {
				senderCC = senderJID.User[:2]
			}
		}

		// Only trim CC if it matches the sender's CC
		if strings.HasPrefix(phoneToCheck, senderCC) && len(phoneToCheck) <= 13 {
			phoneToCheck = strings.TrimPrefix(phoneToCheck, senderCC)
		}

		fmt.Printf("[SendMedia] IsOnWhatsApp checking: %s (from %s, senderCC: %s)\n", phoneToCheck, recipient.User, senderCC)

		// Use 30 second timeout for IsOnWhatsApp check
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		isOnWhatsApp, err := client.IsOnWhatsApp(ctx, []string{phoneToCheck})
		cancel() // Cancel immediately after call

		if err != nil {
			// Log the error but don't fail - try to send anyway
			fmt.Printf("[SendMedia] IsOnWhatsApp check failed for %s: %v (akan tetap coba kirim)\n", phoneToCheck, err)
		} else if len(isOnWhatsApp) > 0 {
			result := isOnWhatsApp[0]
			fmt.Printf("[SendMedia] IsOnWhatsApp result for %s: IsIn=%v, JID=%s\n",
				phoneToCheck, result.IsIn, result.JID.String())

			if !result.IsIn {
				// HEURISTIC: If result is False but the returned JID starts with double country code
				// (e.g. 6241...), it's a false negative due to server mangling.
				if senderCC != "" && strings.HasPrefix(result.JID.User, senderCC) && !strings.HasPrefix(recipient.User, senderCC) {
					fmt.Printf("[SendMedia] Detected false negative for international number (mangled JID: %s). Proceeding anyway.\n", result.JID.String())
				} else {
					return "", ErrUserNotRegistered
				}
			} else {
				// Update recipient to the true JID returned by WhatsApp
				recipient = result.JID
			}
		} else {
			fmt.Printf("[SendMedia] IsOnWhatsApp returned empty result for %s (akan tetap coba kirim)\n", phoneToCheck)
		}
	}

	var data []byte
	var mimeType string

	if strings.HasPrefix(url, "data:") {
		// Parse data URI
		parts := strings.SplitN(url, ",", 2)
		if len(parts) == 2 {
			meta := parts[0]
			b64Data := parts[1]
			
			// Extract mime type
			metaParts := strings.Split(strings.TrimPrefix(meta, "data:"), ";")
			mimeType = metaParts[0]

			// Decode base64
			decoded, err := base64.StdEncoding.DecodeString(b64Data)
			if err != nil {
				return "", fmt.Errorf("failed to decode base64 data URI: %w", err)
			}
			data = decoded
		} else {
			return "", fmt.Errorf("invalid data URI format")
		}
	} else {
		// Use pooled HTTP client
		resp, err := s.httpClient.Get().Get(url)
		if err != nil {
			return "", fmt.Errorf("failed to download media: %w", err)
		}
		defer resp.Body.Close()

		data, err = io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read media body: %w", err)
		}

		mimeType = http.DetectContentType(data)
		if resp.Header.Get("Content-Type") != "" && resp.Header.Get("Content-Type") != "application/octet-stream" {
			mimeType = resp.Header.Get("Content-Type")
		}
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
		errStr := strings.ToLower(err.Error())

		// Auto-reconnect on 400 error logic
		if strings.Contains(errStr, "server returned error 400") || strings.Contains(errStr, "bad request") {
			fmt.Printf("[SendMedia] Received 400 error for token %s. Attempting 1x auto-reconnect...\n", token)
			client.Disconnect()
			time.Sleep(1 * time.Second)
			
			if reconnectErr := client.Connect(); reconnectErr == nil {
				// Retry sending
				fmt.Printf("[SendMedia] Reconnect success, retrying send for token %s...\n", token)
				
				sendResp, err = client.SendMessage(context.Background(), recipient, msg)
				if err != nil {
					retryErrStr := strings.ToLower(err.Error())
					if strings.Contains(retryErrStr, "server returned error 400") || strings.Contains(retryErrStr, "bad request") {
						fmt.Printf("[SendMedia] Send failed again with 400 after reconnect. Purging session for %s...\n", token)
						go s.cleanupSession(token, "Persistent Error 400 on send media")
						return "", err
					}
				}
			} else {
				fmt.Printf("[SendMedia] Reconnect failed for %s: %v. Purging session...\n", token, reconnectErr)
				go s.cleanupSession(token, "Failed to reconnect after 400 error")
				return "", err
			}
		}

		if err != nil {
			errStr = strings.ToLower(err.Error())
			if strings.Contains(errStr, "not on whatsapp") || strings.Contains(errStr, "unknown user") || strings.Contains(errStr, "recipient not found") {
				return "", ErrUserNotRegistered
			}
			return "", err
		}
	}

	// Record Status Message in DB for Analytics
	if recipient.Server == "broadcast" {
		_ = s.Store.Driver.InsertStatusMessage(token, sendResp.ID)
	}

	return sendResp.ID, nil
}

// GetClientCount returns the number of connected clients (for monitoring)
func (s *Service) GetClientCount() int {
	return s.clientPool.Count()
}

// SetStatusMessage updates the user's about/status text
func (s *Service) SetStatusMessage(token, status string) error {
	client, err := s.GetClient(token)
	if err != nil {
		return err
	}
	if !client.IsConnected() {
		return fmt.Errorf("client not connected")
	}

	return client.SetStatusMessage(context.Background(), status)
}


// CheckNumber checks if a number is registered on WhatsApp
func (s *Service) CheckNumber(token, phone string) (bool, string, error) {
	client, err := s.GetClient(token)
	if err != nil {
		return false, "", err
	}
	if !client.IsConnected() {
		return false, "", fmt.Errorf("client not connected")
	}

	phone = NormalizePhone(phone)
	if phone == "" {
		return false, "", fmt.Errorf("invalid phone number")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res, err := client.IsOnWhatsApp(ctx, []string{phone})
	if err != nil {
		return false, "", err
	}

	if len(res) > 0 {
		return res[0].IsIn, res[0].JID.String(), nil
	}

	return false, "", nil
}

// SendPresence sends typing or recording presence to a chat
func (s *Service) SendPresence(token, to, state string) error {
	client, err := s.GetClient(token)
	if err != nil {
		return err
	}
	if !client.IsConnected() {
		return fmt.Errorf("client not connected")
	}

	// Normalize phone number if not already a JID
	if !strings.Contains(to, "@") {
		to = NormalizePhone(to) + "@s.whatsapp.net"
	}
	recipient, err := types.ParseJID(to)
	if err != nil {
		return fmt.Errorf("invalid recipient JID: %w", err)
	}

	var chatState types.ChatPresence
	var chatMedia types.ChatPresenceMedia = types.ChatPresenceMediaText

	switch strings.ToLower(state) {
	case "composing", "typing":
		chatState = types.ChatPresenceComposing
	case "recording", "audio":
		chatState = types.ChatPresenceComposing
		chatMedia = types.ChatPresenceMediaAudio
	case "paused":
		chatState = types.ChatPresencePaused
	default:
		return fmt.Errorf("invalid presence state")
	}

	return client.SendChatPresence(context.Background(), recipient, chatState, chatMedia)
}
