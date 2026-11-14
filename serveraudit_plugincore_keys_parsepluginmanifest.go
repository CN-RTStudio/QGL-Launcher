package main

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

func parsePluginManifest(jarName string, raw []byte) (pluginManifest, []PluginFinding) {
	manifest := pluginManifest{}
	findings := []PluginFinding{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, _, ok := splitPropertyPair(trimmed)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "name":
			manifest.Name = strings.TrimSpace(value)
			if manifest.Name == "" {
				findings = append(findings, PluginFinding{
					Name: jarName, Reason: pluginReasonBadManifest, Detail: "plugin.yml 的 name 为空", Blocking: true,
				})
			} else if utf8.RuneCountInString(manifest.Name) > pluginMaxNameRunes {
				findings = append(findings, PluginFinding{
					Name: jarName, Reason: pluginReasonBadManifest, Detail: "plugin.yml 的 name 过长", Blocking: true,
				})
			}
		case "main":
			manifest.Main = strings.TrimSpace(value)
			if !validJavaClassName(manifest.Main) {
				findings = append(findings, PluginFinding{
					Name: jarName, Reason: pluginReasonBadManifest,
					Detail: fmt.Sprintf("plugin.yml 的 main 不是合法类名: %s", manifest.Main), Blocking: true,
				})
			}
		}
	}
	if manifest.Main == "" {
		findings = append(findings, PluginFinding{
			Name: jarName, Reason: pluginReasonBadManifest, Detail: "plugin.yml 缺少 main", Blocking: true,
		})
	}
	return manifest, findings
}
