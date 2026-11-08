package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	dpReasonOK             = "ok"
	dpReasonMissing        = "missing"
	dpReasonUnreadable     = "unreadable"
	dpReasonTooLarge       = "too-large"
	dpReasonSymlink        = "symlink"
	dpReasonTooMany        = "too-many"
	dpReasonBadZip         = "bad-zip"
	dpReasonEntryEscape    = "entry-escape"
	dpReasonDuplicateName  = "duplicate-entry"
	dpReasonMissingMcmeta  = "missing-mcmeta"
	dpReasonInvalidMcmeta  = "invalid-mcmeta"
	dpReasonBadDescription = "bad-description"
	dpReasonEmptyPack      = "empty-pack"

	dpMaxFileBytes = 64 << 20
	dpMaxEntries   = 8192
	dpMaxPacks     = 32
	dpMaxFindings  = 96
	dpMaxDescLen   = 256
)

var dpRoots = []string{"datapacks", filepath.Join("world", "datapacks")}

type DataPackFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type DataPackAudit struct {
	Dir      string
	Packs    []string
	Findings []DataPackFinding
}

func (a DataPackAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a DataPackAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != dpReasonOK {
			return true
		}
	}
	return false
}

func (a DataPackAudit) Codes() []string {
	seen := map[string]bool{}
	codes := []string{}
	for _, f := range a.Findings {
		if f.Reason == dpReasonOK || seen[f.Reason] {
			continue
		}
		seen[f.Reason] = true
		codes = append(codes, f.Reason)
	}
	sort.Strings(codes)
	return codes
}

func (a DataPackAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现数据包"
	}
	parts := []string{}
	for _, f := range a.Findings {
		where := f.File
		if where == "" {
			where = "server"
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", where, f.Reason))
		if len(parts) >= 6 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

func (a DataPackAudit) Summary() string {
	blocking := 0
	warnings := 0
	for _, f := range a.Findings {
		if f.Blocking {
			blocking++
		} else if f.Reason != dpReasonOK {
			warnings++
		}
	}
	return fmt.Sprintf("packs=%d findings=%d blocking=%d warnings=%d", len(a.Packs), len(a.Findings), blocking, warnings)
}

func (a *DataPackAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= dpMaxFindings {
		return
	}
	a.Findings = append(a.Findings, DataPackFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

type packMeta struct {
	Pack struct {
		PackFormat  int         `json:"pack_format"`
		Description interface{} `json:"description"`
	} `json:"pack"`
}

func packDescription(value interface{}) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case map[string]interface{}:
		if text, ok := v["text"].(string); ok {
			return text, true
		}
		return "", false
	case nil:
		return "", true
	case []interface{}:
		return "", false
	default:
		return "", false
	}
}

func packCheckMeta(audit *DataPackAudit, name string, data []byte) {
	var meta packMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		audit.add(name, dpReasonInvalidMcmeta, "pack.mcmeta 不是合法 JSON", false)
		return
	}
	if meta.Pack.PackFormat <= 0 || meta.Pack.PackFormat > 128 {
		audit.add(name, dpReasonInvalidMcmeta, "pack_format 越界或缺失", false)
	}
	desc, ok := packDescription(meta.Pack.Description)
	if !ok {
		audit.add(name, dpReasonBadDescription, "description 结构不受支持", false)
		return
	}
	if len(desc) > dpMaxDescLen {
		audit.add(name, dpReasonBadDescription, "description 超长", false)
	}
	if packHasControl(desc) {
		audit.add(name, dpReasonBadDescription, "description 含控制字符", false)
	}
}

func packHasControl(value string) bool {
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch < 0x20 && ch != '\t' && ch != '\n' {
			return true
		}
		if ch == 0x7f {
			return true
		}
	}
	return false
}

func packEntryUnsafe(name string) bool {
	if name == "" {
		return true
	}
	if strings.Contains(name, "\x00") || strings.Contains(name, `\`) {
		return true
	}
	if strings.HasPrefix(name, "/") {
		return true
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

func packCheckZip(audit *DataPackAudit, name, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		audit.add(name, dpReasonUnreadable, "数据包不可访问", true)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(name, dpReasonSymlink, "数据包是符号链接", true)
		return
	}
	if !info.Mode().IsRegular() {
		audit.add(name, dpReasonUnreadable, "数据包不是普通文件", true)
		return
	}
	if info.Size() > dpMaxFileBytes {
		audit.add(name, dpReasonTooLarge, "数据包超过体积预算", true)
		return
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		audit.add(name, dpReasonBadZip, "数据包不是合法 zip", true)
		return
	}
	defer reader.Close()
	if len(reader.File) > dpMaxEntries {
		audit.add(name, dpReasonTooMany, "数据包条目数超过预算", true)
		return
	}
	seen := map[string]bool{}
	hasMeta := false
	for _, entry := range reader.File {
		if packEntryUnsafe(entry.Name) {
			audit.add(name, dpReasonEntryEscape, "条目路径可逃逸: "+packShorten(entry.Name), true)
			continue
		}
		lower := strings.ToLower(entry.Name)
		if seen[lower] {
			audit.add(name, dpReasonDuplicateName, "重复条目: "+packShorten(entry.Name), false)
		}
		seen[lower] = true
		if lower == "pack.mcmeta" {
			hasMeta = true
			if entry.UncompressedSize64 > dpMaxFileBytes {
				audit.add(name, dpReasonTooLarge, "pack.mcmeta 解压体积过大", true)
				continue
			}
			file, err := entry.Open()
			if err != nil {
				audit.add(name, dpReasonUnreadable, "pack.mcmeta 不可读", false)
				continue
			}
			data := make([]byte, 0, 64<<10)
			buf := make([]byte, 4096)
			for {
				n, readErr := file.Read(buf)
				if n > 0 {
					data = append(data, buf[:n]...)
					if len(data) > dpMaxFileBytes {
						break
					}
				}
				if readErr != nil {
					break
				}
			}
			file.Close()
			packCheckMeta(audit, name, data)
		}
	}
	if !hasMeta {
		audit.add(name, dpReasonMissingMcmeta, "数据包缺少 pack.mcmeta", false)
	}
	if len(reader.File) == 0 {
		audit.add(name, dpReasonEmptyPack, "数据包为空 zip", false)
	}
}

func AuditServerDataPacks(serverDir string) DataPackAudit {
	audit := DataPackAudit{Dir: serverDir}
	for _, root := range dpRoots {
		dir := filepath.Join(serverDir, root)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				name := filepath.Join(root, entry.Name())
				audit.Packs = append(audit.Packs, name)
				metaPath := filepath.Join(dir, entry.Name(), "pack.mcmeta")
				data, err := readBoundedFile(metaPath, auditTextReadMaxBytes)
				if err != nil {
					audit.add(name, dpReasonMissingMcmeta, "目录数据包缺少 pack.mcmeta", false)
					continue
				}
				packCheckMeta(&audit, name, data)
				continue
			}
			if !strings.HasSuffix(strings.ToLower(entry.Name()), ".zip") {
				continue
			}
			name := filepath.Join(root, entry.Name())
			audit.Packs = append(audit.Packs, name)
			if len(audit.Packs) > dpMaxPacks {
				audit.add(name, dpReasonTooMany, "数据包数量超过预算", true)
				continue
			}
			packCheckZip(&audit, name, filepath.Join(dir, entry.Name()))
		}
	}
	if len(audit.Findings) == 0 {
		audit.add("", dpReasonOK, "未发现数据包", false)
	}
	return audit
}

func packShorten(value string) string {
	if len(value) > 48 {
		return value[:45] + "..."
	}
	return value
}
