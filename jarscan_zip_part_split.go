package main

import (
	"archive/zip"
	"bufio"
	"io"
	"strings"
)

func readManifestHeaders(f *zip.File) map[string]string {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	limited := io.LimitReader(rc, jarScanTextCap)
	sc := bufio.NewScanner(limited)
	sc.Buffer(make([]byte, 0, 64*1024), jarScanTextCap)

	heads := map[string]string{}
	var curKey, curVal string
	flush := func() {
		if curKey != "" {
			heads[strings.ToUpper(curKey)] = strings.TrimSpace(curVal)
		}
		curKey, curVal = "", ""
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		// MANIFEST 续行：以空格或制表符开头的行拼接到上一个值。
		if line[0] == ' ' || line[0] == '\t' {
			curVal += strings.TrimLeft(line, " \t")
			continue
		}
		flush()
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		curKey = line[:colon]
		curVal = strings.TrimSpace(line[colon+1:])
	}
	flush()
	return heads
}

// isJarRootEntry 判断条目是否位于 jar 根目录（不含目录分隔符）。
func isJarRootEntry(lowerName string) bool {
	return !strings.Contains(lowerName, "/")
}

// pathExtLower 返回小写扩展名（含点），无扩展名返回空串。
func pathExtLower(name string) string {
	dot := strings.LastIndexByte(name, '.')
	if dot < 0 || strings.LastIndexByte(name, '/') > dot {
		return ""
	}
	return name[dot:]
}
