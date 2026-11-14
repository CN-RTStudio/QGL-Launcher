package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type CrashReportEntry struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"modTime"`
}

const crashReportListMax = 50

func listCrashReports(mcDir string, limit int) ([]CrashReportEntry, error) {
	if limit <= 0 || limit > crashReportListMax {
		limit = crashReportListMax
	}
	dir := filepath.Join(mcDir, "crash-reports")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	list := make([]CrashReportEntry, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".txt") {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
			continue
		}
		list = append(list, CrashReportEntry{Name: e.Name(), Size: info.Size(), ModTime: info.ModTime()})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].ModTime.Equal(list[j].ModTime) {
			return list[i].Name > list[j].Name
		}
		return list[i].ModTime.After(list[j].ModTime)
	})
	if len(list) > limit {
		list = list[:limit]
	}
	return list, nil
}

func (a *App) ListCrashReports() []CrashReportEntry {
	list, err := listCrashReports(a.GetMinecraftDir(), crashReportListMax)
	if err != nil {
		return []CrashReportEntry{}
	}
	return list
}

func (a *App) GetCrashReportTail(name string) string {
	if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, "/\\") {
		return ""
	}
	if !strings.HasSuffix(strings.ToLower(name), ".txt") {
		return ""
	}
	path := filepath.Join(a.GetMinecraftDir(), "crash-reports", name)
	text, truncated, err := readLogTail(path, logViewMaxBytes)
	if err != nil || text == "" {
		return ""
	}
	return redactLogBody(wrapTruncatedLog(text, truncated, logViewMaxBytes))
}
