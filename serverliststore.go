package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	serverListStoreVersion  = 1
	serverListStoreMaxBytes = 256 << 10
	serverListStoreMaxEntry = 512
	serverListStoreNameRune = 96
	serverListStoreHostRune = 255
	serverListStoreFilePerm = 0600
	serverListStoreDirPerm  = 0700
)

type SavedServerEntry struct {
	Name    string `json:"name"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Kind    string `json:"kind"`
	AddedAt int64  `json:"addedAt"`
}

type ServerListStore struct {
	Version   int                `json:"version"`
	UpdatedAt int64              `json:"updatedAt"`
	Entries   []SavedServerEntry `json:"entries"`
}

type ServerListImportResult struct {
	Accepted   []SavedServerEntry
	Rejected   []string
	Warnings   []string
	Duplicates int
	Private    int
}

func serverListEntryKey(host string, port int) string {
	return strings.ToLower(strings.TrimSpace(host)) + "|" + strconv.Itoa(port)
}

func serverListAddress(host string, port int) string {
	return net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(port))
}

func serverListKindLabel(kind ServerKind) string {
	switch kind {
	case ServerKindLoopback:
		return "loopback"
	case ServerKindPrivate:
		return "private"
	case ServerKindIP:
		return "ip"
	default:
		return "hostname"
	}
}

func normalizeSavedServerEntry(entry SavedServerEntry) (SavedServerEntry, error) {
	host := strings.TrimSpace(entry.Host)
	if host == "" {
		return SavedServerEntry{}, errors.New("saved server host is empty")
	}
	if len([]rune(host)) > serverListStoreHostRune {
		return SavedServerEntry{}, errors.New("saved server host is too long")
	}
	if hasControlCharStr(host) || strings.ContainsAny(host, " \t\"';,<>/\\") {
		return SavedServerEntry{}, errors.New("saved server host contains forbidden characters")
	}
	if entry.Port < 1 || entry.Port > 65535 {
		return SavedServerEntry{}, errors.New("saved server port is out of range")
	}
	parsed, err := ParseServerAddress(serverListAddress(host, entry.Port), ServerListLimits{})
	if err != nil {
		return SavedServerEntry{}, fmt.Errorf("saved server address is invalid: %w", err)
	}
	name := SanitizeServerName(entry.Name, ServerListLimits{})
	if name == "" {
		name = parsed.Host
	}
	addedAt := entry.AddedAt
	if addedAt <= 0 {
		addedAt = time.Now().Unix()
	}
	return SavedServerEntry{
		Name:    name,
		Host:    parsed.Host,
		Port:    parsed.Port,
		Kind:    serverListKindLabel(parsed.Kind),
		AddedAt: addedAt,
	}, nil
}

func normalizeSavedServerEntries(entries []SavedServerEntry) ([]SavedServerEntry, []string) {
	out := make([]SavedServerEntry, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	var rejected []string
	for _, entry := range entries {
		clean, err := normalizeSavedServerEntry(entry)
		if err != nil {
			rejected = append(rejected, err.Error())
			continue
		}
		key := serverListEntryKey(clean.Host, clean.Port)
		if _, ok := seen[key]; ok {
			rejected = append(rejected, "duplicate saved server entry: "+key)
			continue
		}
		if len(out) >= serverListStoreMaxEntry {
			rejected = append(rejected, "saved server entry limit reached")
			break
		}
		seen[key] = struct{}{}
		out = append(out, clean)
	}
	return out, rejected
}

func cleanSavedServerEntries(entries []SavedServerEntry) ([]SavedServerEntry, []string) {
	out := make([]SavedServerEntry, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	var rejected []string
	for _, entry := range entries {
		clean, err := normalizeSavedServerEntry(entry)
		if err != nil {
			rejected = append(rejected, err.Error())
			continue
		}
		key := serverListEntryKey(clean.Host, clean.Port)
		if _, ok := seen[key]; ok {
			continue
		}
		if len(out) >= serverListStoreMaxEntry {
			break
		}
		seen[key] = struct{}{}
		out = append(out, clean)
	}
	return out, rejected
}

func ImportServerListText(text string, existing []SavedServerEntry, now time.Time) ServerListImportResult {
	var result ServerListImportResult
	entries, lineErrs := ParseServerListText(text, ServerListLimits{MaxLines: serverListStoreMaxEntry})
	for _, lineErr := range lineErrs {
		result.Rejected = append(result.Rejected, lineErr)
	}
	cleanExisting, _ := normalizeSavedServerEntries(existing)
	keys := make(map[string]struct{}, len(cleanExisting)+len(entries))
	for _, entry := range cleanExisting {
		keys[serverListEntryKey(entry.Host, entry.Port)] = struct{}{}
	}
	stamp := now.Unix()
	for _, entry := range entries {
		if entry.Kind == ServerKindPrivate || entry.Kind == ServerKindLoopback {
			result.Private++
			result.Warnings = append(result.Warnings, "server "+serverListAddress(entry.Host, entry.Port)+" targets a private or loopback address")
		}
		key := serverListEntryKey(entry.Host, entry.Port)
		if _, ok := keys[key]; ok {
			result.Duplicates++
			continue
		}
		if len(result.Accepted) >= serverListStoreMaxEntry {
			result.Rejected = append(result.Rejected, "import entry limit reached")
			break
		}
		name := SanitizeServerName(entry.Name, ServerListLimits{})
		if name == "" {
			name = entry.Host
		}
		keys[key] = struct{}{}
		result.Accepted = append(result.Accepted, SavedServerEntry{
			Name:    name,
			Host:    entry.Host,
			Port:    entry.Port,
			Kind:    serverListKindLabel(entry.Kind),
			AddedAt: stamp,
		})
	}
	return result
}

func DescribeServerListImport(result ServerListImportResult) string {
	return fmt.Sprintf("imported=%d rejected=%d duplicates=%d private=%d warnings=%d",
		len(result.Accepted), len(result.Rejected), result.Duplicates, result.Private, len(result.Warnings))
}

func serverListStorePath(qglDir string) string {
	return filepath.Join(qglDir, "QGL", "servers.json")
}

func auditServerListStorePath(path string, root string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("server list store path is empty")
	}
	if _, ok := PathWithin(root, path); !ok {
		return "", errors.New("server list store path escapes the qgl directory")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve server list store path: %w", err)
	}
	return absolutePath, nil
}

func ReadServerListStore(path string, root string) (ServerListStore, error) {
	cleanPath, err := auditServerListStorePath(path, root)
	if err != nil {
		return ServerListStore{}, err
	}
	store := ServerListStore{Version: serverListStoreVersion}
	err = readLocalJSONBounded(cleanPath, &store, serverListStoreMaxBytes, "服务器列表")
	if errors.Is(err, fs.ErrNotExist) {
		return ServerListStore{Version: serverListStoreVersion, Entries: []SavedServerEntry{}}, nil
	}
	if err != nil {
		return ServerListStore{}, err
	}
	if store.Version != serverListStoreVersion {
		return ServerListStore{}, fmt.Errorf("unsupported server list store version: %d", store.Version)
	}
	clean, rejected := normalizeSavedServerEntries(store.Entries)
	if len(rejected) > 0 {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionRejected,
			"serverlist", "服务器列表载入时丢弃非法条目: "+rejected[0])
	}
	store.Entries = clean
	return store, nil
}

func WriteServerListStore(path string, root string, entries []SavedServerEntry, now time.Time) error {
	cleanPath, err := auditServerListStorePath(path, root)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cleanPath), serverListStoreDirPerm); err != nil {
		return fmt.Errorf("create server list directory: %w", err)
	}
	clean, rejected := cleanSavedServerEntries(entries)
	if len(rejected) > 0 {
		return fmt.Errorf("server list entry rejected: %s", rejected[0])
	}
	store := ServerListStore{
		Version:   serverListStoreVersion,
		UpdatedAt: now.Unix(),
		Entries:   clean,
	}
	if err := writePrivateJSON(cleanPath, store); err != nil {
		return err
	}
	if err := os.Chmod(cleanPath, serverListStoreFilePerm); err != nil {
		return fmt.Errorf("tighten server list permissions: %w", err)
	}
	return nil
}

func (a *App) GetSavedServerList() (ServerListStore, error) {
	root := a.GetQGLDir()
	return ReadServerListStore(serverListStorePath(root), root)
}

func (a *App) ImportServerList(text string) (ServerListImportResult, error) {
	root := a.GetQGLDir()
	path := serverListStorePath(root)
	store, err := ReadServerListStore(path, root)
	if err != nil {
		return ServerListImportResult{}, err
	}
	result := ImportServerListText(text, store.Entries, time.Now())
	if len(result.Accepted) == 0 {
		return result, fmt.Errorf("no server entry was accepted: %s", DescribeServerListImport(result))
	}
	merged := append(store.Entries, result.Accepted...)
	if err := WriteServerListStore(path, root, merged, time.Now()); err != nil {
		return result, err
	}
	recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityInfo, auditActionDetected,
		"serverlist", "导入服务器列表: "+DescribeServerListImport(result))
	return result, nil
}

func (a *App) RemoveSavedServer(host string, port int) error {
	root := a.GetQGLDir()
	path := serverListStorePath(root)
	store, err := ReadServerListStore(path, root)
	if err != nil {
		return err
	}
	key := serverListEntryKey(host, port)
	kept := make([]SavedServerEntry, 0, len(store.Entries))
	removed := 0
	for _, entry := range store.Entries {
		if serverListEntryKey(entry.Host, entry.Port) == key {
			removed++
			continue
		}
		kept = append(kept, entry)
	}
	if removed == 0 {
		return fmt.Errorf("saved server not found: %s", key)
	}
	if err := WriteServerListStore(path, root, kept, time.Now()); err != nil {
		return err
	}
	recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityInfo, auditActionDetected,
		"serverlist", fmt.Sprintf("移除服务器条目 %s removed=%d", key, removed))
	return nil
}
