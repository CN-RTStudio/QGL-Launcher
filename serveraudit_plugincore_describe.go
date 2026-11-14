package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
