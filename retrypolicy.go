package main

import (
	"context"
	"time"
)

const retryBackoffMax = 30 * time.Second

func retryDelay(attempt int, base time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := base
	for i := 1; i < attempt; i++ {
		if d <= 0 {
			return time.Second
		}
		if d >= retryBackoffMax/2 {
			return retryBackoffMax
		}
		d *= 2
	}
	if d <= 0 {
		return time.Second
	}
	if d > retryBackoffMax {
		return retryBackoffMax
	}
	return d
}

func runWithRetry(ctx context.Context, attempts int, base time.Duration,
	step func() (bool, error)) (int, error) {

	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		fatal, err := step()
		if err == nil {
			return attempt, nil
		}
		lastErr = err
		if fatal || attempt == attempts {
			return attempt, lastErr
		}
		select {
		case <-time.After(retryDelay(attempt, base)):
		case <-ctx.Done():
			return attempt, ctx.Err()
		}
	}
	return attempts, lastErr
}
