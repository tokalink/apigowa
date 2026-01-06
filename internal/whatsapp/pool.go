package whatsapp

import (
	"container/list"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"go.mau.fi/whatsmeow"
)

const (
	defaultMaxClients     = 1000
	defaultIdleTimeout    = 30 * time.Minute
	defaultWorkerPoolSize = 100
	defaultHTTPPoolSize   = 100
	numShards             = 16
)

// ClientEntry represents a client in the pool
type ClientEntry struct {
	Client     *whatsmeow.Client
	Token      string
	LastAccess time.Time
	element    *list.Element
}

// ShardedLock provides sharded locking to reduce contention
type ShardedLock struct {
	locks [numShards]sync.RWMutex
}

func (s *ShardedLock) getShard(key string) int {
	hash := 0
	for _, c := range key {
		hash = 31*hash + int(c)
	}
	if hash < 0 {
		hash = -hash
	}
	return hash % numShards
}

func (s *ShardedLock) Lock(key string) {
	s.locks[s.getShard(key)].Lock()
}

func (s *ShardedLock) Unlock(key string) {
	s.locks[s.getShard(key)].Unlock()
}

func (s *ShardedLock) RLock(key string) {
	s.locks[s.getShard(key)].RLock()
}

func (s *ShardedLock) RUnlock(key string) {
	s.locks[s.getShard(key)].RUnlock()
}

// ClientPool manages WhatsApp clients with LRU eviction
type ClientPool struct {
	clients     map[string]*ClientEntry
	lruList     *list.List
	globalMu    sync.RWMutex
	shardedLock ShardedLock
	maxClients  int
	idleTimeout time.Duration
	cleanupStop chan struct{}
}

// PoolConfig holds configuration for the client pool
type PoolConfig struct {
	MaxClients     int
	IdleTimeout    time.Duration
	WorkerPoolSize int
	HTTPPoolSize   int
}

// NewPoolConfigFromEnv creates PoolConfig from environment variables
func NewPoolConfigFromEnv() *PoolConfig {
	maxClients := getEnvInt("MAX_CLIENTS", defaultMaxClients)
	idleTimeout := getEnvInt("CLIENT_IDLE_TIMEOUT", 30)
	workerPoolSize := getEnvInt("WORKER_POOL_SIZE", defaultWorkerPoolSize)
	httpPoolSize := getEnvInt("HTTP_POOL_SIZE", defaultHTTPPoolSize)

	return &PoolConfig{
		MaxClients:     maxClients,
		IdleTimeout:    time.Duration(idleTimeout) * time.Minute,
		WorkerPoolSize: workerPoolSize,
		HTTPPoolSize:   httpPoolSize,
	}
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil {
			return intVal
		}
	}
	return defaultVal
}

// NewClientPool creates a new client pool
func NewClientPool(cfg *PoolConfig) *ClientPool {
	pool := &ClientPool{
		clients:     make(map[string]*ClientEntry),
		lruList:     list.New(),
		maxClients:  cfg.MaxClients,
		idleTimeout: cfg.IdleTimeout,
		cleanupStop: make(chan struct{}),
	}

	// Start background cleanup goroutine
	go pool.cleanupLoop()

	return pool
}

// Get retrieves a client from the pool, returns nil if not found
func (p *ClientPool) Get(token string) *whatsmeow.Client {
	p.shardedLock.RLock(token)
	entry, exists := p.clients[token]
	p.shardedLock.RUnlock(token)

	if !exists {
		return nil
	}

	// Update access time and move to front of LRU
	p.globalMu.Lock()
	entry.LastAccess = time.Now()
	p.lruList.MoveToFront(entry.element)
	p.globalMu.Unlock()

	return entry.Client
}

// Put adds or updates a client in the pool
func (p *ClientPool) Put(token string, client *whatsmeow.Client) {
	p.shardedLock.Lock(token)
	defer p.shardedLock.Unlock(token)

	// Check if already exists
	if entry, exists := p.clients[token]; exists {
		entry.Client = client
		entry.LastAccess = time.Now()
		p.globalMu.Lock()
		p.lruList.MoveToFront(entry.element)
		p.globalMu.Unlock()
		return
	}

	// Check if we need to evict
	p.globalMu.Lock()
	for p.lruList.Len() >= p.maxClients {
		p.evictOldest()
	}

	// Add new entry
	entry := &ClientEntry{
		Client:     client,
		Token:      token,
		LastAccess: time.Now(),
	}
	entry.element = p.lruList.PushFront(entry)
	p.globalMu.Unlock()

	p.clients[token] = entry
}

// Remove removes a client from the pool
func (p *ClientPool) Remove(token string) {
	p.shardedLock.Lock(token)
	defer p.shardedLock.Unlock(token)

	entry, exists := p.clients[token]
	if !exists {
		return
	}

	p.globalMu.Lock()
	p.lruList.Remove(entry.element)
	p.globalMu.Unlock()

	delete(p.clients, token)

	// Disconnect the client
	if entry.Client != nil && entry.Client.IsConnected() {
		entry.Client.Disconnect()
	}
}

// evictOldest removes the oldest entry (must be called with globalMu locked)
func (p *ClientPool) evictOldest() {
	elem := p.lruList.Back()
	if elem == nil {
		return
	}

	entry := elem.Value.(*ClientEntry)
	p.lruList.Remove(elem)

	// Need to unlock/relock for sharded lock
	token := entry.Token

	// Remove from map (we need to be careful here with locks)
	go func() {
		p.shardedLock.Lock(token)
		delete(p.clients, token)
		p.shardedLock.Unlock(token)

		// Disconnect client
		if entry.Client != nil && entry.Client.IsConnected() {
			fmt.Printf("[Pool] Evicting idle client: %s\n", token)
			entry.Client.Disconnect()
		}
	}()
}

// cleanupLoop periodically removes idle clients
func (p *ClientPool) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanupIdle()
		case <-p.cleanupStop:
			return
		}
	}
}

// cleanupIdle removes clients that have been idle for too long
func (p *ClientPool) cleanupIdle() {
	now := time.Now()
	var toRemove []string

	p.globalMu.RLock()
	for token, entry := range p.clients {
		if now.Sub(entry.LastAccess) > p.idleTimeout {
			toRemove = append(toRemove, token)
		}
	}
	p.globalMu.RUnlock()

	for _, token := range toRemove {
		fmt.Printf("[Pool] Removing idle client (timeout): %s\n", token)
		p.Remove(token)
	}
}

// Count returns the number of clients in the pool
func (p *ClientPool) Count() int {
	p.globalMu.RLock()
	defer p.globalMu.RUnlock()
	return len(p.clients)
}

// Stop stops the cleanup goroutine
func (p *ClientPool) Stop() {
	close(p.cleanupStop)
}

// WorkerPool manages a pool of worker goroutines
type WorkerPool struct {
	tasks    chan func()
	wg       sync.WaitGroup
	stopChan chan struct{}
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(size int) *WorkerPool {
	wp := &WorkerPool{
		tasks:    make(chan func(), size*10), // Buffer for pending tasks
		stopChan: make(chan struct{}),
	}

	for i := 0; i < size; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}

	return wp
}

func (wp *WorkerPool) worker() {
	defer wp.wg.Done()
	for {
		select {
		case task := <-wp.tasks:
			if task != nil {
				task()
			}
		case <-wp.stopChan:
			return
		}
	}
}

// Submit submits a task to the worker pool
func (wp *WorkerPool) Submit(task func()) {
	select {
	case wp.tasks <- task:
	default:
		// Pool is full, run synchronously
		go task()
	}
}

// Stop stops all workers
func (wp *WorkerPool) Stop() {
	close(wp.stopChan)
	wp.wg.Wait()
}

// HTTPClientPool provides a shared HTTP client with connection pooling
type HTTPClientPool struct {
	client *http.Client
}

// NewHTTPClientPool creates a new HTTP client pool
func NewHTTPClientPool(poolSize int) *HTTPClientPool {
	transport := &http.Transport{
		MaxIdleConns:        poolSize,
		MaxIdleConnsPerHost: poolSize / 2,
		MaxConnsPerHost:     poolSize,
		IdleConnTimeout:     90 * time.Second,
	}

	return &HTTPClientPool{
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}
}

// Get returns the shared HTTP client
func (p *HTTPClientPool) Get() *http.Client {
	return p.client
}
