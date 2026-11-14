package main

import (
	"strings"
)

func splitWindowsDrive(p string) (root, rest string) {
	if len(p) >= 2 && p[1] == ':' {
		return p[:2], p[2:]
	}
	if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//") {
		segs := strings.Split(strings.TrimLeft(p, `\/`), `\/`)
		if len(segs) >= 3 {
			return `\\` + segs[0] + `\` + segs[1] + `\`, strings.Join(segs[2:], `\`)
		}
		return `\\` + strings.Join(segs, `\`), ""
	}
	if strings.HasPrefix(p, `/`) || strings.HasPrefix(p, `\`) {
		// Unix 风格绝对路径：整条视为 root，供测试与类 Unix 平台复用。
		return "", ""
	}
	return "", ""
}

func safePathList(systemEntries []string, javaDir string) []string {
	seen := make(map[string]bool, len(systemEntries)+1)
	var out []string
	appendEntry := func(e string) {
		key := strings.ToLower(strings.TrimRight(strings.TrimSpace(strings.Trim(e, `"'`)), `\/`))
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, e)
	}
	for _, e := range systemEntries {
		if isSystemDirEntry(e) {
			appendEntry(strings.TrimSpace(e))
		}
	}
	if javaDir != "" {
		appendEntry(javaDir)
	}
	return out
}
