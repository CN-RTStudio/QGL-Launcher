package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	pluginReasonOK          = "ok"
	pluginReasonSymlink     = "symlink"
	pluginReasonNotDir      = "not-directory"
	pluginReasonTooLarge    = "too-large"
	pluginReasonBadZip      = "bad-zip"
	pluginReasonBadEntry    = "bad-entry"
	pluginReasonTooMany     = "too-many-entries"
	pluginReasonBadManifest = "bad-manifest"
	pluginReasonDuplicate   = "duplicate-name"
	pluginReasonExecutable  = "executable-file"
	pluginMaxCount          = 256
	pluginMaxBytes          = 64 << 20
	pluginMaxEntries        = 10000
	pluginMaxDirEntries     = 2048
	pluginMaxManifestBytes  = 256 << 10
	pluginMaxNameRunes      = 64
	pluginMaxClassChars     = 255
)

var pluginDangerousExt = map[string]bool{
	".exe": true, ".bat": true, ".cmd": true, ".com": true,
	".scr": true, ".ps1": true, ".sh": true, ".dll": true,
	".vbs": true, ".js": true, ".jar.exe": true,
}

type PluginFinding struct {
	Name     string
	Reason   string
	Detail   string
	Blocking bool
}

type ServerPluginAudit struct {
	Dir      string
	Present  bool
	Jars     int
	Findings []PluginFinding
}

type pluginManifest struct {
	Name string
	Main string
}

func (a ServerPluginAudit) Blocking() bool {
	for _, finding := range a.Findings {
		if finding.Blocking {
			return true
		}
	}
	return false
}

func (a ServerPluginAudit) HasWarnings() bool {
	for _, finding := range a.Findings {
		if !finding.Blocking {
			return true
		}
	}
	return false
}

func (a ServerPluginAudit) Describe() string {
	if len(a.Findings) == 0 {
		return fmt.Sprintf("插件目录共 %d 个 jar，未发现异常", a.Jars)
	}
	parts := make([]string, 0, len(a.Findings))
	for _, finding := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s: %s", finding.Name, finding.Detail))
	}
	return strings.Join(parts, "；")
}

func auditPluginJar(path, name string) ([]PluginFinding, pluginManifest, error) {
	manifest := pluginManifest{}
	info, err := os.Stat(path)
	if err != nil {
		return nil, manifest, err
	}
	if info.Size() > pluginMaxBytes {
		return []PluginFinding{{
			Name: name, Reason: pluginReasonTooLarge,
			Detail: fmt.Sprintf("jar 体积 %d 超过上限 %d", info.Size(), pluginMaxBytes), Blocking: true,
		}}, manifest, nil
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		return []PluginFinding{{
			Name: name, Reason: pluginReasonBadZip, Detail: "jar 无法作为 zip 打开", Blocking: true,
		}}, manifest, nil
	}
	defer reader.Close()
	if len(reader.File) > pluginMaxEntries {
		return []PluginFinding{{
			Name: name, Reason: pluginReasonTooMany,
			Detail: fmt.Sprintf("jar 条目数 %d 超过上限 %d", len(reader.File), pluginMaxEntries), Blocking: true,
		}}, manifest, nil
	}
	findings := []PluginFinding{}
	var manifestFile *zip.File
	for _, file := range reader.File {
		if suspiciousServerJarEntry(file.Name) {
			findings = append(findings, PluginFinding{
				Name: name, Reason: pluginReasonBadEntry,
				Detail: fmt.Sprintf("jar 条目路径越界: %s", file.Name), Blocking: true,
			})
			continue
		}
		if strings.EqualFold(filepath.Base(file.Name), "plugin.yml") && manifestFile == nil {
			manifestFile = file
		}
	}
	if manifestFile == nil {
		findings = append(findings, PluginFinding{
			Name: name, Reason: pluginReasonBadManifest, Detail: "缺少 plugin.yml", Blocking: false,
		})
		return findings, manifest, nil
	}
	if manifestFile.UncompressedSize64 > pluginMaxManifestBytes {
		findings = append(findings, PluginFinding{
			Name: name, Reason: pluginReasonBadManifest, Detail: "plugin.yml 体积超限", Blocking: true,
		})
		return findings, manifest, nil
	}
	raw, err := readZipEntryBounded(manifestFile, pluginMaxManifestBytes)
	if err != nil {
		return nil, manifest, err
	}
	parsed, parseFindings := parsePluginManifest(name, raw)
	findings = append(findings, parseFindings...)
	manifest = parsed
	return findings, manifest, nil
}
