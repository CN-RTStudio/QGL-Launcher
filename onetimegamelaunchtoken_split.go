package main

import (
	"time"
)

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
