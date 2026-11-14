package main

import (
	"os"
	"path/filepath"
	"strings"
)

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
