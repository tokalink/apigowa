package whatsapp

import (
	"math"
	"sync"
	"time"

	"github.com/purpshell/meowcaller"
)

// SilenceDetectorSink wraps a WAVRecorder and detects silence.
type SilenceDetectorSink struct {
	mu               sync.Mutex
	WavFile          string
	Threshold        float64
	SilenceDuration  time.Duration
	OnSilenceDetected func(wavFile string)
	
	recorder         meowcaller.AudioSink
	silenceStart     time.Time
	isTalking        bool
	isFinished       bool
}

func NewSilenceDetectorSink(wavFile string, threshold float64, silenceDuration time.Duration, onSilence func(string)) (*SilenceDetectorSink, error) {
	recorder, err := meowcaller.WAVRecorder(wavFile)
	if err != nil {
		return nil, err
	}

	return &SilenceDetectorSink{
		WavFile:          wavFile,
		Threshold:        threshold,
		SilenceDuration:  silenceDuration,
		OnSilenceDetected: onSilence,
		recorder:         recorder,
		silenceStart:     time.Now(),
		isTalking:        false,
	}, nil
}

func (s *SilenceDetectorSink) WriteFrame(frame []float32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isFinished {
		return nil // Ignore frames after finished
	}

	// Forward to underlying WAV recorder
	if s.recorder != nil {
		s.recorder.WriteFrame(frame)
	}

	// Calculate RMS amplitude
	rms := calculateRMS(frame)

	if rms > s.Threshold {
		// User is talking
		s.isTalking = true
		s.silenceStart = time.Time{} // Reset silence timer
	} else {
		// User is silent
		if s.isTalking {
			if s.silenceStart.IsZero() {
				s.silenceStart = time.Now()
			} else if time.Since(s.silenceStart) >= s.SilenceDuration {
				// Silence detected for X duration after talking
				s.isFinished = true
				if s.OnSilenceDetected != nil {
					go s.OnSilenceDetected(s.WavFile)
				}
			}
		} else {
			// Not talked yet, maybe timeout if they never talk?
			// For simplicity, we just wait until they talk.
			// Optional: add overall timeout here.
			if s.silenceStart.IsZero() {
				s.silenceStart = time.Now()
			} else if time.Since(s.silenceStart) >= 10*time.Second {
				// 10 seconds of absolute silence (never talked), abort
				s.isFinished = true
				if s.OnSilenceDetected != nil {
					go s.OnSilenceDetected(s.WavFile)
				}
			}
		}
	}

	return nil
}

func (s *SilenceDetectorSink) Close() error {
	if s.recorder != nil {
		return s.recorder.Close()
	}
	return nil
}

// calculateRMS calculates Root Mean Square of float32 samples
func calculateRMS(frame []float32) float64 {
	if len(frame) == 0 {
		return 0
	}
	
	var sumSquares float64
	
	for _, sample := range frame {
		val := float64(sample)
		sumSquares += val * val
	}
	
	return math.Sqrt(sumSquares / float64(len(frame)))
}
