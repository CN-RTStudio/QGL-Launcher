package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

func truncateStartupLine(line string) string {
	line = strings.TrimSpace(line)
	if len(line) <= startupTruncatedDetailRunes {
		return sanitizeLogLine(line)
	}
	return sanitizeLogLine(line[:startupTruncatedDetailRunes]) + "..."
}

func readStartupScript(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, startupMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > startupMaxBytes {
		return nil, fmt.Errorf("脚本超过 %d 字节", startupMaxBytes)
	}
	return data, nil
}
