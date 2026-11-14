package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

)

func mavenNameToURL(name string) string {
	parts := strings.Split(name, ":")
	if len(parts) < 3 {
		return ""
	}

	group := strings.ReplaceAll(parts[0], ".", "/")
	artifact := parts[1]
	version := parts[2]
	classifier := ""
	if len(parts) >= 4 {
		classifier = "-" + parts[3]
	}

	fileName := fmt.Sprintf("%s-%s%s.jar", artifact, version, classifier)
	return fmt.Sprintf("https://repo1.maven.org/maven2/%s/%s/%s/%s", group, artifact, version, fileName)
}

// extractNatives 从 jar 中提取 dll/jnilib/so 文件到目标目录
// 返回提取的文件数量
// 增强：处理损坏的 jar 文件、清理多余文件（参考 PCL 的 McLaunchNatives）
func extractNatives(jarPath string, destDir string) (int, error) {
	r, err := zip.OpenReader(jarPath)
	if err != nil {
		// 损坏的 jar 文件，删除它（参考 PCL：删除损坏的 Natives 文件）
		os.Remove(jarPath)
		return 0, fmt.Errorf("打开 Natives 文件失败（文件可能已损坏）: %s", jarPath)
	}
	defer r.Close()

	count := 0
	var extractedFiles []string // 记录本次提取的文件名，用于清理多余文件

	for _, f := range r.File {
		// 跳过目录和 META-INF
		if f.FileInfo().IsDir() {
			continue
		}
		if strings.HasPrefix(f.Name, "META-INF/") {
			continue
		}

		// 只提取 .dll, .jnilib, .so 文件
		lowerName := strings.ToLower(f.Name)
		if !strings.HasSuffix(lowerName, ".dll") &&
			!strings.HasSuffix(lowerName, ".jnilib") &&
			!strings.HasSuffix(lowerName, ".so") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		fileName := filepath.Base(f.Name)
		destPath := filepath.Join(destDir, fileName)
		extractedFiles = append(extractedFiles, destPath)

		// 如果文件已存在且大小相同，跳过（参考PCL）
		if info, err := os.Stat(destPath); err == nil && info.Size() == f.FileInfo().Size() {
			rc.Close()
			count++
			continue
		}

		// 文件存在但大小不同，删除旧文件（参考 PCL）
		if _, err := os.Stat(destPath); err == nil {
			os.Remove(destPath)
		}

		out, err := os.Create(destPath)
		if err != nil {
			rc.Close()
			continue
		}

		_, err = io.Copy(out, rc)
		out.Close()
		rc.Close()
		if err != nil {
			continue
		}
		count++
	}

	return count, nil
}

// extractNativesFromJSON 从版本 JSON 的 libraries 中提取 natives
// 增强：支持 natives-windows-64 键、处理损坏的 jar（参考 PCL 的 McLaunchNatives）
