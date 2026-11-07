package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	bxaMaxFindings = 16
	bxaMaxFile     = 256 * 1024
	bxaMaxReason   = 256
	bxaMaxWildcard = "0.0.0.0/0"
	bxaIPFile      = "banned-ips.json"
	bxaPlayerFile  = "banned-players.json"
	bxaMiss        = "ban-file-missing"
	bxaRead        = "ban-file-unreadable"
	bxaLink        = "ban-file-symlink"
	bxaEmpty       = "ban-file-empty"
	bxaJSON        = "ban-json-invalid"
	bxaShape       = "ban-entry-invalid"
	bxaWildcard    = "ban-wildcard-scope"
	bxaStale       = "ban-entry-stale"
	bxaReasonCtl   = "ban-reason-control"
	bxaReasonLong  = "ban-reason-too-long"
	bxaDupTarget   = "ban-target-duplicate"
)

var bxaCIDRPattern = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$`)

type BanAuditFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type BanAudit struct {
	ServerDir string
	Findings  []BanAuditFinding
}

type bxaEntry struct {
	UUID     string `json:"uuid"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
	Reason   string `json:"reason"`
	Created  string `json:"created"`
	Source   string `json:"source"`
	Expires  string `json:"expires"`
	TargetID string `json:"targetId"`
}

func (a *BanAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= bxaMaxFindings {
		return
	}
	a.Findings = append(a.Findings, BanAuditFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *BanAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *BanAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *BanAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "封禁名单配置处于安全区间"
	}
	sorted := make([]BanAuditFinding, len(a.Findings))
	copy(sorted, a.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].File != sorted[j].File {
			return sorted[i].File < sorted[j].File
		}
		if sorted[i].Reason != sorted[j].Reason {
			return sorted[i].Reason < sorted[j].Reason
		}
		return sorted[i].Detail < sorted[j].Detail
	})
	var b strings.Builder
	for i, f := range sorted {
		if i >= 10 {
			b.WriteString(fmt.Sprintf("…等 %d 项", len(sorted)))
			break
		}
		if i > 0 {
			b.WriteString("；")
		}
		b.WriteString(f.File)
		b.WriteString("/")
		b.WriteString(f.Reason)
		if f.Detail != "" {
			b.WriteString("(")
			b.WriteString(f.Detail)
			b.WriteString(")")
		}
	}
	return b.String()
}

func bxaLoad(serverDir, name string, a *BanAudit) ([]bxaEntry, bool) {
	path := filepath.Join(serverDir, name)
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		a.add(name, bxaMiss, "缺少封禁名单文件", false)
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(name, bxaRead, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(name, bxaLink, "封禁名单是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, bxaMaxFile)
	if err != nil {
		a.add(name, bxaRead, err.Error(), true)
		return nil, false
	}
	text := strings.TrimPrefix(strings.TrimSpace(string(data)), "\ufeff")
	if text == "" {
		a.add(name, bxaEmpty, "封禁名单为空文件", false)
		return nil, false
	}
	var entries []bxaEntry
	if err := json.Unmarshal([]byte(text), &entries); err != nil {
		a.add(name, bxaJSON, err.Error(), true)
		return nil, false
	}
	return entries, true
}

func bxaTargetKey(entry bxaEntry) string {
	if id := strings.TrimSpace(entry.TargetID); id != "" {
		return "id:" + strings.ToLower(id)
	}
	if ip := strings.TrimSpace(entry.IP); ip != "" {
		return "ip:" + ip
	}
	if uuid := strings.TrimSpace(entry.UUID); uuid != "" {
		return "uuid:" + strings.ToLower(uuid)
	}
	if name := strings.TrimSpace(entry.Name); name != "" {
		return "name:" + strings.ToLower(name)
	}
	return ""
}

func bxaReasonHasControl(reason string) bool {
	return strings.ContainsAny(reason, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x1b")
}

func bxaExpired(entry bxaEntry) bool {
	expires := strings.TrimSpace(entry.Expires)
	if expires == "" || strings.EqualFold(expires, "forever") {
		return false
	}
	for _, layout := range []string{"2006-01-02 15:04:05 -0700", time.RFC3339} {
		if t, err := time.Parse(layout, expires); err == nil {
			return t.Before(time.Now())
		}
	}
	return false
}

func bxaAuditEntry(fileName string, entry bxaEntry, index int, seen map[string]int, a *BanAudit) {
	label := fmt.Sprintf("#%d", index)
	key := bxaTargetKey(entry)
	if key == "" {
		a.add(fileName, bxaShape, label+" 缺少可识别的封禁对象", true)
	}
	if first, ok := seen[key]; ok && key != "" {
		a.add(fileName, bxaDupTarget, fmt.Sprintf("%s 与 #%d 指向同一对象", label, first), true)
	} else if key != "" {
		seen[key] = index
	}
	ip := strings.TrimSpace(entry.IP)
	if ip == bxaMaxWildcard || ip == "*" || ip == "0.0.0.0" {
		a.add(fileName, bxaWildcard, label+" 封禁范围覆盖全部地址", true)
	} else if bxaCIDRPattern.MatchString(ip) {
		if prefix := ip[strings.Index(ip, "/")+1:]; prefix == "0" {
			a.add(fileName, bxaWildcard, label+" CIDR 前缀为 0，覆盖全部地址", true)
		}
	}
	if bxaExpired(entry) {
		a.add(fileName, bxaStale, label+" 封禁已过期但未清理", false)
	}
	reason := entry.Reason
	if bxaReasonHasControl(reason) {
		a.add(fileName, bxaReasonCtl, label+" 封禁理由含控制字符", true)
	}
	if len(reason) > bxaMaxReason {
		a.add(fileName, bxaReasonLong, fmt.Sprintf("%s 理由长度 %d 超过上限", label, len(reason)), false)
	}
}

func AuditServerBans(serverDir string) *BanAudit {
	a := &BanAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(bxaIPFile, bxaMiss, "未配置服务器目录", false)
		return a
	}
	for _, name := range []string{bxaIPFile, bxaPlayerFile} {
		entries, ok := bxaLoad(serverDir, name, a)
		if !ok {
			continue
		}
		seen := map[string]int{}
		for i, entry := range entries {
			if bxaTargetKey(entry) == "" && entry.Reason == "" && entry.Expires == "" {
				a.add(name, bxaShape, fmt.Sprintf("#%d 是空条目", i), true)
				continue
			}
			bxaAuditEntry(name, entry, i, seen, a)
		}
	}
	return a
}
