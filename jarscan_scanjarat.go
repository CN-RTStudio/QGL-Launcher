package main

import (
	"archive/zip"
	"fmt"
)

func scanJarAt(jarPath string) (*JarScanReport, error) {
	zr, err := zip.OpenReader(jarPath)
	if err != nil {
		return nil, fmt.Errorf("打开 jar 失败: %v", err)
	}
	defer zr.Close()
	return scanZipReader(&zr.Reader), nil
}

func scanZipReader(zr *zip.Reader) *JarScanReport {
	rep := &JarScanReport{Findings: []JarFinding{}, ruleSeen: map[string]bool{}}
	nestedCount, nestedBytes := 0, 0
	scanZipInto(rep, zr, 1, "", &nestedCount, &nestedBytes)
	rep.finalize()
	return rep
}
