package main

// modpackinstalllock.go —— 整合包安装并发闸门。
//
// 同时触发两个 mrpack 安装任务会写同一个 .minecraft 目录，造成半解压状态、
// 覆盖式写穿和 mods 目录污染。这里把"这个实例此刻能不能开始装整合包"收敛成
// 一个进程内纯函数状态机，避免调用方自己加锁。

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

// ModpackInstallLock 按实例目录路径串行化安装任务。
type ModpackInstallLock struct {
	mu    sync.Mutex
	held  map[string]time.Time
	ttl   time.Duration
	nowFn func() time.Time
}

// NewModpackInstallLock 构造一个锁，ttl 是死锁自动回收时间。
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

// Acquire 尝试拿到某实例的安装锁。
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
