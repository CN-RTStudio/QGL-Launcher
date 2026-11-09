package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// OnetimeLaunchTokenStore 进程内一次性令牌库。
type OnetimeLaunchTokenStore struct {
	mu     sync.Mutex
	tokens map[string]time.Time
	ttl    time.Duration
}

// NewOnetimeLaunchTokenStore ttl<=0 默认 5 分钟。
func NewOnetimeLaunchTokenStore(ttl time.Duration) *OnetimeLaunchTokenStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &OnetimeLaunchTokenStore{
		tokens: make(map[string]time.Time),
		ttl:    ttl,
	}
}

// Issue 生成一个新令牌字符串并登记。
func (s *OnetimeLaunchTokenStore) Issue() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(buf)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	s.tokens[tok] = time.Now().Add(s.ttl)
	return tok, nil
}
