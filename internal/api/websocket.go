package api

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/purpshell/meowcaller"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for the dashboard
	},
}

// WebSocketSink implements meowcaller.AudioSink to forward caller's audio to the CS/AI via WebSocket.
type WebSocketSink struct {
	mu   sync.Mutex
	conn *websocket.Conn
}

func (w *WebSocketSink) WriteFrame(frame []float32) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Convert []float32 to 16-bit PCM little endian
	buf := new(bytes.Buffer)
	for _, sample := range frame {
		// Clamp sample between -1 and 1
		if sample > 1.0 {
			sample = 1.0
		} else if sample < -1.0 {
			sample = -1.0
		}
		
		intSample := int16(sample * 32767.0)
		if err := binary.Write(buf, binary.LittleEndian, intSample); err != nil {
			return err
		}
	}

	// Send binary message to websocket
	w.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	return w.conn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
}

func (w *WebSocketSink) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return nil
}

func (s *Server) StreamCallHandler(c *gin.Context) {
	callID := c.Query("call_id")
	mode := c.Query("mode")
	action := c.Query("action")
	if callID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "call_id is required"})
		return
	}

	// Lookup call in active registry
	call, ok := s.Service.GetActiveCall(callID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "call not found or already ended"})
		return
	}

	// Upgrade connection to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		fmt.Printf("Failed to upgrade websocket: %v\n", err)
		return
	}
	defer conn.Close()
	defer call.Hangup() // Automatically end the call if WebSocket disconnects

	// If it's an inbound call and we are asked to answer it
	if action == "answer" {
		if call.State() == meowcaller.CallPhaseRinging {
			fmt.Printf("WebSocket requested answering call %s\n", callID)
			call.Answer()
		}
	}

	// 1. Forward incoming audio from WhatsApp to WebSocket (CS Speaker)
	sink := &WebSocketSink{conn: conn}
	call.Receive(sink)
	defer call.Receive(nil) // Detach when done

	// 2. Forward outgoing audio from WebSocket (CS Mic) to WhatsApp
	var pw *io.PipeWriter
	var pr *io.PipeReader
	if mode == "mic" {
		pr, pw = io.Pipe()
		defer pr.Close()
		defer pw.Close()
		// We will NOT call call.Play() here. We wait until it's answered.
	}

	var stateMu sync.Mutex
	var isAnswered bool

	// Notify when answered and close ws when call ends
	go func() {
		for {
			state := call.State()
			
			stateMu.Lock()
			ans := isAnswered
			stateMu.Unlock()

			if !ans && state == meowcaller.CallPhaseActive {
				stateMu.Lock()
				isAnswered = true
				stateMu.Unlock()

				sink.mu.Lock()
				conn.WriteMessage(websocket.TextMessage, []byte(`{"event":"answered"}`))
				sink.mu.Unlock()
				
				if mode == "mic" && pr != nil {
					// Delaying call.Play until Answered prevents WebRTC ICE blocking!
					player := call.Play(meowcaller.PCMStream(pr))
					// Clean up player when the call ends
					call.OnEnd(func(reason string) {
						player.Stop()
					})
				}
			}
			if state == meowcaller.CallPhaseEnded {
				conn.Close() // This breaks the ReadMessage loop below
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()

	// Read loop: receive binary messages from CS Mic and write to pipe
	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			fmt.Printf("WebSocket read error: %v\n", err)
			break
		}

		if messageType == websocket.BinaryMessage {
			stateMu.Lock()
			ans := isAnswered
			stateMu.Unlock()

			// Only write to the pipe if the call is answered to prevent blocking
			if mode == "mic" && ans && pw != nil {
				// Write raw 16kHz s16le PCM to the pipe
				_, err = pw.Write(p)
				if err != nil {
					if !strings.Contains(err.Error(), "closed pipe") {
						fmt.Printf("Pipe write error: %v\n", err)
					}
					break
				}
			}
		} else if messageType == websocket.TextMessage {
			// Frontend might send text messages (e.g. commands)
			// Ignore for now
		}
	}
}
