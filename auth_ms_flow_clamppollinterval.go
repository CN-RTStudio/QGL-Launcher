package main

import (
	"time"
)

func clampPollInterval(seconds int) time.Duration {
	if seconds < int(deviceCodeMinInterval/time.Second) {
		return deviceCodeMinInterval
	}
	d := time.Duration(seconds) * time.Second
	if d > deviceCodeMaxInterval {
		return deviceCodeMaxInterval
	}
	return d
}
func clampDeviceTTL(seconds int) time.Duration {
	if seconds <= 0 {
		return deviceCodeDefaultTTL
	}
	d := time.Duration(seconds) * time.Second
	if d > deviceCodeMaxTTL {
		return deviceCodeMaxTTL
	}
	return d
}
