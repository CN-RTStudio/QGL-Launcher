package main

import (
	"encoding/json"
	"strings"
)

func extractModID(base string, data []byte) string {
	switch base {
	case "fabric.mod.json", "quilt.mod.json":
		var payload struct {
			ID    string `json:"id"`
			Quilt struct {
				ID string `json:"id"`
			} `json:"quilt_loader"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			return ""
		}
		if strings.TrimSpace(payload.ID) != "" {
			return strings.TrimSpace(payload.ID)
		}
		return strings.TrimSpace(payload.Quilt.ID)
	case "mods.toml":
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "modId") {
				_, value, _, ok := splitPropertyPair(trimmed)
				if ok {
					return strings.Trim(strings.TrimSpace(value), "\"'")
				}
			}
		}
	case "mcmod.info":
		var payload []struct {
			ModID string `json:"modid"`
		}
		if err := json.Unmarshal(data, &payload); err != nil || len(payload) == 0 {
			return ""
		}
		return strings.TrimSpace(payload[0].ModID)
	}
	return ""
}
