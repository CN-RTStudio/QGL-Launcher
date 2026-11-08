package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	jvrMaxFindings = 12
	jvrMaxSidecar  = 4 * 1024
	jvrMaxJar      = 512 * 1024 * 1024
	jvrJarName     = "server.jar"
	jvrSidecarName = "server.jar.sha1"
	jvrMiss        = "jar-file-missing"
	jvrRead        = "jar-file-unreadable"
	jvrLink        = "jar-file-symlink"
	jvrEmpty       = "jar-file-empty"
	jvrTooBig      = "jar-file-oversized"
	jvrSidecarMiss = "jar-sha1-missing"
	jvrSidecarRead = "jar-sha1-unreadable"
	jvrSidecarForm = "jar-sha1-malformed"
	jvrDigest      = "jar-sha1-mismatch"
)

type JarIntegrityFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type JarIntegrityAudit struct {
	ServerDir string
	Digest    string
	Findings  []JarIntegrityFinding
}

func (a *JarIntegrityAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= jvrMaxFindings {
		return
	}
	a.Findings = append(a.Findings, JarIntegrityFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *JarIntegrityAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a *JarIntegrityAudit) HasWarnings() bool {
	return len(a.Findings) > 0
}

func (a *JarIntegrityAudit) Describe() string {
	return describeAuditFindings("服务端 jar 与 SHA1 校验文件一致", a.Findings, 8,
		func(f JarIntegrityFinding) []string {
			return []string{f.Reason, f.File}
		},
		func(f JarIntegrityFinding) string {
			return f.Reason
		})
}

func jvrHashJar(path string, limit int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	h := sha1.New()
	if _, err := io.Copy(h, io.LimitReader(file, limit)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func jvrReadSidecar(path string) (string, error) {
	data, err := readBoundedFile(path, jvrMaxSidecar)
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	if fields := strings.Fields(text); len(fields) > 0 {
		return strings.ToLower(fields[0]), nil
	}
	return "", nil
}

func AuditServerJarIntegrity(serverDir string) *JarIntegrityAudit {
	a := &JarIntegrityAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(jvrJarName, jvrMiss, "未配置服务器目录", false)
		return a
	}
	jarPath := filepath.Join(serverDir, jvrJarName)
	info, err := os.Stat(jarPath)
	if err != nil || info.IsDir() {
		a.add(jvrJarName, jvrMiss, "缺少服务端 jar", true)
		return a
	}
	link, err := isSymlinkOrSpecial(jarPath)
	if err != nil {
		a.add(jvrJarName, jvrRead, err.Error(), true)
		return a
	}
	if link {
		a.add(jvrJarName, jvrLink, "服务端 jar 是符号链接或特殊文件", true)
		return a
	}
	if info.Size() == 0 {
		a.add(jvrJarName, jvrEmpty, "服务端 jar 是空文件", true)
		return a
	}
	if info.Size() > jvrMaxJar {
		a.add(jvrJarName, jvrTooBig, fmt.Sprintf("jar 体积 %d 超过上限 %d", info.Size(), int64(jvrMaxJar)), false)
	}
	digest, err := jvrHashJar(jarPath, jvrMaxJar)
	if err != nil {
		a.add(jvrJarName, jvrRead, err.Error(), true)
		return a
	}
	a.Digest = digest

	sidecarPath := filepath.Join(serverDir, jvrSidecarName)
	if _, err := os.Stat(sidecarPath); err != nil {
		a.add(jvrSidecarName, jvrSidecarMiss, "缺少 SHA1 校验文件，无法证明 jar 未被替换", false)
		return a
	}
	link, err = isSymlinkOrSpecial(sidecarPath)
	if err != nil {
		a.add(jvrSidecarName, jvrSidecarRead, err.Error(), true)
		return a
	}
	if link {
		a.add(jvrSidecarName, jvrSidecarRead, "校验文件是符号链接或特殊文件", true)
		return a
	}
	expected, err := jvrReadSidecar(sidecarPath)
	if err != nil {
		a.add(jvrSidecarName, jvrSidecarRead, err.Error(), true)
		return a
	}
	if expected == "" || len(expected) != 40 || !isHexLower(expected) {
		a.add(jvrSidecarName, jvrSidecarForm, "校验文件不是 40 位十六进制 SHA1", true)
		return a
	}
	if expected != digest {
		a.add(jvrJarName, jvrDigest, "jar 实际 SHA1 与校验文件不符", true)
	}
	return a
}

func isHexLower(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
