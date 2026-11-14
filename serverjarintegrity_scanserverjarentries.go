package main

import (
	"archive/zip"
	"fmt"
)

func scanServerJarEntries(path string) (int, []string, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return 0, nil, err
	}
	defer reader.Close()
	var suspicious []string
	count := 0
	for _, entry := range reader.File {
		count++
		if count > serverJarMaxEntries {
			suspicious = append(suspicious, fmt.Sprintf("条目数超过 %d", serverJarMaxEntries))
			return count, suspicious, nil
		}
		if suspiciousServerJarEntry(entry.Name) {
			suspicious = append(suspicious, entry.Name)
		}
		if entry.UncompressedSize64 > uint64(serverJarMaxEntryBytes) {
			suspicious = append(suspicious, fmt.Sprintf("%s 展开后超过上限", entry.Name))
		}
	}
	return count, suspicious, nil
}
