package whatsapp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"mime/multipart"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
	"strings"

	"github.com/purpshell/meowcaller"
)

func (s *Service) MakeCall(token string, to string, audioFile string, interactiveWebhook string) (string, error) {
	callClientIface, ok := s.callClients.Load(token)
	if !ok {
		return "", fmt.Errorf("client not found or not initialized with meowcaller")
	}

	callClient := callClientIface.(*meowcaller.Client)

	if !strings.Contains(to, "@") {
		// Clean up the phone number (basic)
		to = strings.ReplaceAll(to, "+", "")
		to = strings.ReplaceAll(to, "-", "")
		to = strings.ReplaceAll(to, " ", "")
		
		// Indonesian prefix 0 to 62
		if strings.HasPrefix(to, "0") {
			to = "62" + to[1:]
		}
		to = to + "@s.whatsapp.net"
	}

	call, err := callClient.Call(context.Background(), to)
	if err != nil {
		return "", fmt.Errorf("failed to initiate call: %w", err)
	}

	// Register call for streaming
	s.RegisterCall(call.ID(), call)

	go func() {
		// Download audio file if it's a URL
		var tempMp3 string
		if audioFile != "" && strings.HasPrefix(audioFile, "http") {
			tempMp3 = fmt.Sprintf("call_audio_%s_%d.mp3", call.ID(), time.Now().UnixNano())
			if err := downloadFile(audioFile, tempMp3); err == nil {
				audioFile = tempMp3
				// Do not defer os.Remove here! It will delete the file before the call is answered.
			} else {
				fmt.Printf("Failed to download audio: %v\n", err)
				call.Hangup()
				return
			}
		}

		// Clean up downloaded file when the call completely ends
		call.OnEnd(func(reason string) {
			if tempMp3 != "" {
				os.Remove(tempMp3)
			}
		})

		// Wait for the receiver to pick up the call before playing audio
		call.OnPeerAccept(func() {
			go func() {
				// Add a 2-second delay so it sounds natural when the user answers
				time.Sleep(2 * time.Second)
				
				if interactiveWebhook != "" {
					// Start Interactive AI Mode
					StartInteractiveSession(call, audioFile, interactiveWebhook)
				} else if audioFile != "" {
					// Just play once and hang up
					if mp3, err := meowcaller.MP3File(audioFile); err == nil {
						player := call.Play(mp3)
						player.OnFinish(func() {
							call.Hangup()
						})
					} else {
						fmt.Printf("Failed to load MP3 for outbound call: %v\n", err)
						call.Hangup()
					}
				}
			}()
		})
	}()

	return call.ID(), nil
}

// StartInteractiveSession handles the conversational loop
func StartInteractiveSession(call *meowcaller.Call, initialAudio string, webhookURL string) {
	// Function to start listening
	var startListening func()
	
	startListening = func() {
		// Create temporary wav file
		wavFileName := fmt.Sprintf("record_%s_%d.wav", call.ID(), time.Now().UnixNano())
		
		sink, err := NewSilenceDetectorSink(wavFileName, 0.05, 2*time.Second, func(savedFile string) {
			// Silence detected, stop listening
			call.Receive(nil) // Detach sink
			
			// Send to Webhook
			go processInteractiveWebhook(call, savedFile, webhookURL, startListening)
		})
		
		if err != nil {
			fmt.Printf("Failed to create silence detector: %v\n", err)
			return
		}
		
		// Attach sink to receive audio
		call.Receive(sink)
	}

	// Play initial audio first, then start listening
	if initialAudio != "" {
		if mp3, err := meowcaller.MP3File(initialAudio); err == nil {
			player := call.Play(mp3)
			player.OnFinish(func() {
				startListening()
			})
		} else {
			startListening()
		}
	} else {
		startListening()
	}
}

func processInteractiveWebhook(call *meowcaller.Call, wavFile string, webhookURL string, onFinish func()) {
	// Post the wavFile to webhookURL
	// This would involve multipart form-data.
	// We'll implement this HTTP post next.
	// For now, let's just simulate playing a reply and looping.
	// Actually we should implement the POST.
	err := sendWavToWebhook(wavFile, webhookURL, call, onFinish)
	if err != nil {
		fmt.Printf("Interactive webhook failed: %v\n", err)
		call.Hangup()
	}
}

// sendWavToWebhook uploads the WAV file via multipart/form-data
// and expects a JSON response with {"reply_audio": "path_or_url.mp3"}
func sendWavToWebhook(wavFile string, webhookURL string, call *meowcaller.Call, onFinish func()) error {
	defer os.Remove(wavFile) // Clean up temp file

	file, err := os.Open(wavFile)
	if err != nil {
		return err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	
	// Add file
	part, err := writer.CreateFormFile("audio", filepath.Base(wavFile))
	if err != nil {
		return err
	}
	io.Copy(part, file)
	writer.Close()

	// Create request
	req, err := http.NewRequest("POST", webhookURL, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Parse response
	var result struct {
		ReplyAudio string `json:"reply_audio"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}

	if result.ReplyAudio == "" {
		// No reply, hang up
		call.Hangup()
		return nil
	}

	// Wait, if it's a URL, meowcaller.MP3File requires a local file or URL?
	// meowcaller.MP3File likely only supports local files.
	// If it's a URL, we need to download it first.
	audioPath := result.ReplyAudio
	if strings.HasPrefix(audioPath, "http") {
		tempMp3 := fmt.Sprintf("reply_%s_%d.mp3", call.ID(), time.Now().UnixNano())
		if err := downloadFile(audioPath, tempMp3); err == nil {
			audioPath = tempMp3
			defer os.Remove(tempMp3) // Clean up downloaded file
		} else {
			return fmt.Errorf("failed to download reply audio: %v", err)
		}
	}

	if mp3, err := meowcaller.MP3File(audioPath); err == nil {
		player := call.Play(mp3)
		player.OnFinish(func() {
			onFinish()
		})
	} else {
		return fmt.Errorf("failed to load reply MP3: %v", err)
	}

	return nil
}

func downloadFile(url string, filepath string) error {
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}
