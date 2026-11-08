package main

// onetimegamelaunchtoken.go —— 启动器↔游戏进程一次性握手令牌。
//
// Wails 前端通过本地 IPC 唤起游戏，游戏进程可能反连回启动器做状态汇报。
// 如果端口是固定的，任意本地进程都能伪装成游戏上报"启动成功"。这里生成
// 一个一次性 token，只在启动这一次传给游戏，游戏必须原样回带才被接受。

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

// Consume 校验并消费令牌（一次性：用一次就废）。
func (s *OnetimeLaunchTokenStore) Consume(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	exp, ok := s.tokens[tok]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.tokens, tok)
		return false
	}
	delete(s.tokens, tok)
	return true
}

// Len 当前未消费令牌数（监控用）。
func (s *OnetimeLaunchTokenStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens)
}

func (s *OnetimeLaunchTokenStore) gcLocked() {
	now := time.Now()
	for k, exp := range s.tokens {
		if now.After(exp) {
			delete(s.tokens, k)
		}
	}
}
