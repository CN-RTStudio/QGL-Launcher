package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// modsScanMaxJars 限制单次启动前最多扫描的 jar 数量。
	modsScanMaxJars = 2000
)

type ModJarRisk struct {
	Path         string   `json:"path"`
	FileName     string   `json:"fileName"`
	Blocked      bool     `json:"blocked"`
	JarCritical  int      `json:"jarCritical"`
	Log4Critical int      `json:"log4Critical"`
	Warnings     int      `json:"warnings"`
	Reasons      []string `json:"reasons"`
	ScanError    string   `json:"scanError,omitempty"`
}
type ModDirScanReport struct {
	ScannedDirs  []string     `json:"scannedDirs"`
	ScannedJars  int          `json:"scannedJars"`
	Skipped      int          `json:"skipped"`
	Risks        []ModJarRisk `json:"risks"`
	Blocked      bool         `json:"blocked"`
	LimitReached bool         `json:"limitReached"`
}

func (a *App) resolveModsDirs(versionID string) []string {
	mcDir := a.GetMinecraftDir()
	seen := map[string]bool{}
	dirs := []string{}

	add := func(d string) {
		if d == "" {
			return
		}
		if abs, err := filepath.Abs(d); err == nil {
			d = abs
		}
		if !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}

	add(filepath.Join(mcDir, "mods"))
	if a.isVersionIsolated() && versionID != "" {
		add(filepath.Join(mcDir, "versions", versionID, "mods"))
	}
	return dirs
}

func listEnabledJars(dir string) ([]string, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
		return nil, 0, err
	}

	jars := []string{}
	skipped := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".jar") {
			// 非 jar（.jar.disabled 因后缀不是 .jar 也在此被排除）不参与加载，跳过。
			continue
		}
		if len(jars) >= modsScanMaxJars {
			skipped++
			continue
		}
		jars = append(jars, filepath.Join(dir, name))
	}
	sort.Strings(jars)
	return jars, skipped, nil
}
