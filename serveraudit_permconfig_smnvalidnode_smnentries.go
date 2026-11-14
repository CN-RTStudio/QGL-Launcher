package main

import (
	"strings"
)

func smnEntries(text string) []smnEntry {
	type frame struct {
		indent int
		key    string
	}
	stack := make([]frame, 0, 8)
	out := make([]smnEntry, 0, 32)
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		indent := 0
		for indent < len(raw) && raw[indent] == ' ' {
			indent++
		}
		trimmed := strings.TrimSpace(raw)
		for len(stack) > 0 && indent <= stack[len(stack)-1].indent && !strings.HasPrefix(trimmed, "- ") {
			stack = stack[:len(stack)-1]
		}
		if strings.HasPrefix(trimmed, "- ") {
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			item = cfgStripQuotes(item)
			path := ""
			if len(stack) > 0 {
				path = stack[len(stack)-1].key
			}
			out = append(out, smnEntry{Path: path, Value: item})
			continue
		}
		sep := strings.Index(trimmed, ":")
		if sep < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:sep])
		value := strings.TrimSpace(trimmed[sep+1:])
		for len(stack) > 0 && indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}
		path := key
		if len(stack) > 0 {
			path = stack[len(stack)-1].key + "." + key
		}
		stack = append(stack, frame{indent: indent, key: path})
		if value != "" {
			out = append(out, smnEntry{Path: path, Value: cfgStripQuotes(value)})
		}
	}
	return out
}

const (
	plugPermReasonOK              = "ok"
	plugPermReasonMissing         = "missing"
	plugPermReasonUnreadable      = "unreadable"
	plugPermReasonTooLarge        = "too-large"
	plugPermReasonTooMany         = "too-many"
	plugPermReasonWildcard        = "wildcard-permission"
	plugPermReasonWildcardPlugin  = "wildcard-plugin-permission"
	plugPermReasonOpDefault       = "op-default"
	plugPermReasonEveryPermission = "every-permission-key"
	plugPermMaxFiles              = 60
	plugPermMaxFileBytes          = 512 << 10
	plugPermMaxFindings           = 96
	plugPermMaxDepth              = 3
)

var plugPermFileNames = map[string]bool{
	"config.yml":       true,
	"config.yaml":      true,
	"permissions.yml":  true,
	"permissions.yaml": true,
	"settings.yml":     true,
	"settings.yaml":    true,
	"groups.yml":       true,
	"groups.yaml":      true,
}

type PluginPermFinding struct {
	File     string
	Line     int
	Reason   string
	Detail   string
	Blocking bool
}

type PluginPermissionAudit struct {
	Dir      string
	Files    int
	Findings []PluginPermFinding
}
