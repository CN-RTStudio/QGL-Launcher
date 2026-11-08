package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	libReasonOK               = "ok"
	libReasonMissing          = "missing"
	libReasonUnreadable       = "unreadable"
	libReasonTooLarge         = "too-large"
	libReasonSymlink          = "symlink"
	libReasonTooMany          = "too-many"
	libReasonNotAJar          = "not-a-jar"
	libReasonDuplicateVersion = "duplicate-version"
	libReasonShadowCopy       = "shadow-copy"
	libReasonBadName          = "bad-name"
	libReasonWorldWritable    = "world-writable"

	libMaxFileBytes = 256 << 20
	libMaxFiles     = 512
	libMaxDepth     = 6
	libMaxFindings  = 96
)

var libRoots = []string{"libs", "libraries"}

type LibraryFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type LibraryAudit struct {
	Dir      string
	Jars     []string
	Findings []LibraryFinding
}

func (a LibraryAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f LibraryFinding) bool { return f.Blocking })
}

func (a LibraryAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != libReasonOK {
			return true
		}
	}
	return false
}

func (a LibraryAudit) Codes() []string {
	seen := map[string]bool{}
	codes := []string{}
	for _, f := range a.Findings {
		if f.Reason == libReasonOK || seen[f.Reason] {
			continue
		}
		seen[f.Reason] = true
		codes = append(codes, f.Reason)
	}
	sort.Strings(codes)
	return codes
}

func (a LibraryAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现依赖库"
	}
	parts := []string{}
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s(%s)", f.File, f.Reason))
		if len(parts) >= 4 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

func (a LibraryAudit) Summary() string {
	blocking, warnings := 0, 0
	for _, f := range a.Findings {
		if f.Blocking {
			blocking++
		} else if f.Reason != libReasonOK {
			warnings++
		}
	}
	return fmt.Sprintf("jars=%d findings=%d blocking=%d warnings=%d", len(a.Jars), len(a.Findings), blocking, warnings)
}

func (a *LibraryAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= libMaxFindings {
		return
	}
	a.Findings = append(a.Findings, LibraryFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func libArtifactKey(name string) string {
	lower := strings.ToLower(strings.TrimSuffix(filepath.Base(name), filepath.Ext(name)))
	for _, marker := range []string{"-sources", "-javadoc", "-natives"} {
		lower = strings.TrimSuffix(lower, marker)
	}
	segments := strings.Split(lower, "-")
	kept := []string{}
	for _, segment := range segments {
		if segment == "" || libLooksVersion(segment) {
			continue
		}
		kept = append(kept, segment)
	}
	if len(kept) == 0 {
		return lower
	}
	return strings.Join(kept, "-")
}

func libLooksVersion(segment string) bool {
	digits, alpha := 0, 0
	for i := 0; i < len(segment); i++ {
		ch := segment[i]
		if ch >= '0' && ch <= '9' {
			digits++
			continue
		}
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			alpha++
		}
	}
	if digits == 0 {
		return false
	}
	return digits >= alpha
}

func libNameSane(name string) bool {
	if name == "" || len(name) > 160 {
		return false
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if ch < 0x20 || ch == 0x7f {
			return false
		}
	}
	return true
}

func libLooksLikeZip(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 4)
	n, err := f.Read(head)
	if err != nil && n < 4 {
		return false
	}
	return string(head) == "PK\x03\x04" || string(head) == "PK\x05\x06"
}

func libCollect(audit *LibraryAudit, root, rel string, depth int) {
	if depth > libMaxDepth {
		audit.add(rel, libReasonTooMany, "依赖库目录层级超出预算", true)
		return
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		audit.add(rel, libReasonUnreadable, "依赖库目录不可读", true)
		return
	}
	for _, entry := range entries {
		if len(audit.Jars) >= libMaxFiles {
			audit.add(rel, libReasonTooMany, "依赖库文件数量超过预算", true)
			return
		}
		childPath := filepath.Join(root, entry.Name())
		childRel := filepath.Join(rel, entry.Name())
		if entry.IsDir() {
			libCollect(audit, childPath, childRel, depth+1)
			continue
		}
		lower := strings.ToLower(entry.Name())
		if !strings.HasSuffix(lower, ".jar") {
			if strings.HasSuffix(lower, ".jar.old") || strings.HasSuffix(lower, ".jar.disabled") || strings.HasSuffix(lower, ".jar.bak") {
				audit.add(childRel, libReasonShadowCopy, "遗留的禁用/备份 jar", false)
			}
			continue
		}
		if !libNameSane(entry.Name()) {
			audit.add(childRel, libReasonBadName, "jar 名含控制字符", true)
			continue
		}
		info, err := os.Lstat(childPath)
		if err != nil {
			audit.add(childRel, libReasonUnreadable, "jar 不可访问", true)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			audit.add(childRel, libReasonSymlink, "jar 是符号链接", true)
			continue
		}
		if !info.Mode().IsRegular() {
			audit.add(childRel, libReasonUnreadable, "jar 不是普通文件", true)
			continue
		}
		if info.Size() > libMaxFileBytes {
			audit.add(childRel, libReasonTooLarge, "jar 超过体积预算", true)
			continue
		}
		if info.Mode().Perm()&0o022 != 0 {
			audit.add(childRel, libReasonWorldWritable, "jar 对其他用户可写", false)
		}
		if !libLooksLikeZip(childPath) {
			audit.add(childRel, libReasonNotAJar, "文件头不是 zip/jar", false)
		}
		audit.Jars = append(audit.Jars, childRel)
	}
}

func AuditServerLibraries(serverDir string) LibraryAudit {
	audit := LibraryAudit{Dir: serverDir}
	keys := map[string]string{}
	for _, rootName := range libRoots {
		root := filepath.Join(serverDir, rootName)
		if _, err := os.Stat(root); err != nil {
			continue
		}
		libCollect(&audit, root, rootName, 0)
	}
	if len(audit.Jars) == 0 {
		if len(audit.Findings) == 0 {
			audit.add("", libReasonMissing, "未发现 libs/libraries 目录", false)
		}
		audit.add("", libReasonOK, "无依赖库归档", false)
		return audit
	}
	for _, jar := range audit.Jars {
		key := libArtifactKey(jar)
		if key == "" {
			continue
		}
		if prev, ok := keys[key]; ok {
			audit.add(jar, libReasonDuplicateVersion, "同一构件多版本共存，与 "+prev+" 冲突", false)
			continue
		}
		keys[key] = jar
	}
	if len(audit.Findings) == 0 {
		audit.add("", libReasonOK, "依赖库结构正常", false)
	}
	return audit
}
