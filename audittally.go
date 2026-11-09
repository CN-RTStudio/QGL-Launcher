package main

func auditTally[F any](findings []F, blocking func(F) bool, warning func(F) bool) (int, int) {
	blockingCount, warningCount := 0, 0
	for _, f := range findings {
		if blocking(f) {
			blockingCount++
			continue
		}
		if warning(f) {
			warningCount++
		}
	}
	return blockingCount, warningCount
}
