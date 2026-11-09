package main

import (
	"encoding/json"
	"os"
)

func wlLoadEntries(path string) ([]wlEntry, string) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, wlReasonMissing
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, wlReasonSymlink
	}
	if !info.Mode().IsRegular() {
		return nil, wlReasonUnreadable
	}
	if info.Size() > wlMaxFileBytes {
		return nil, wlReasonTooLarge
	}
	data, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		return nil, wlReasonUnreadable
	}
	var entries []wlEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, wlReasonInvalidJSON
	}
	return entries, ""
}

func wlLoadRawShape(path string) (bool, string) {
	data, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		return false, wlReasonUnreadable
	}
	var probe []map[string]interface{}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false, wlReasonInvalidJSON
	}
	for _, item := range probe {
		if _, ok := item["uuid"]; !ok {
			return false, wlReasonBadShape
		}
	}
	return true, ""
}
