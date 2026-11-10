package main

import (
	"errors"
	"sync"
	"time"
)

var (
	// ErrModpackBusy 已有另一个安装任务在跑。
	ErrModpackBusy = errors.New("modpack install already in progress")
	// ErrModpackNotLocked 当前没有持锁，不能释放。
	ErrModpackNotLocked = errors.New("no modpack install lock held")
)

type ModpackInstallLock struct {
	mu    sync.Mutex
	held  map[string]time.Time
	ttl   time.Duration
	nowFn func() time.Time
}

func NewModpackInstallLock(ttl time.Duration) *ModpackInstallLock {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &ModpackInstallLock{
		held:  make(map[string]time.Time),
		ttl:   ttl,
		nowFn: time.Now,
	}
}

func (l *ModpackInstallLock) Acquire(instanceDir string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.nowFn()
	// 顺手清理过期持锁（上次进程崩了没放）。
	for dir, until := range l.held {
		if now.After(until) {
			delete(l.held, dir)
		}
	}
	if _, busy := l.held[instanceDir]; busy {
		return ErrModpackBusy
	}
	l.held[instanceDir] = now.Add(l.ttl)
	return nil
}

// Release 释放某实例的安装锁。
func (l *ModpackInstallLock) Release(instanceDir string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.held[instanceDir]; !ok {
		return ErrModpackNotLocked
	}
	delete(l.held, instanceDir)
	return nil
}

// HeldDirs 调试/测试用：当前持锁的实例列表。
func (l *ModpackInstallLock) HeldDirs() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.held))
	for d := range l.held {
		out = append(out, d)
	}
	return out
}
