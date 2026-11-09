package main

import "time"

const (
	serverExitPollInterval = 100 * time.Millisecond
	serverExitWaitTimeout  = 5 * time.Second
)

func waitForServerStop(stillRunning func() bool, timeout, interval time.Duration) bool {
	if stillRunning == nil {
		return true
	}
	if timeout <= 0 {
		timeout = serverExitWaitTimeout
	}
	if interval <= 0 {
		interval = serverExitPollInterval
	}
	deadline := time.Now().Add(timeout)
	for {
		if !stillRunning() {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(interval)
	}
}

func serverStillRunning() bool {
	serverMgr.mu.Lock()
	defer serverMgr.mu.Unlock()
	return serverMgr.status.Running
}
