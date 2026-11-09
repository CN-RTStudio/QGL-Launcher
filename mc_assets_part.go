package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func extractNativesWithLimits(jarPath string, destDir string, entryMax, totalMax int64) (int, error) {
	r, err := zip.OpenReader(jarPath)
	if err != nil {
		os.Remove(jarPath)
		return 0, fmt.Errorf("打开 Natives 文件失败（文件可能已损坏）: %s", jarPath)
	}
	defer r.Close()
	count := 0
	var total int64
	for _, f := range r.File {
		if f.FileInfo().IsDir() || strings.HasPrefix(f.Name, "META-INF/") {
			continue
		}
		// 符号链接 / 设备等特殊条目绝不落地，即便伪装成 .dll 后缀。
		if f.Mode()&(os.ModeSymlink|os.ModeDevice|os.ModeNamedPipe|os.ModeSocket) != 0 {
			continue
		}
		lowerName := strings.ToLower(f.Name)
		if !strings.HasSuffix(lowerName, ".dll") && !strings.HasSuffix(lowerName, ".jnilib") && !strings.HasSuffix(lowerName, ".so") {
			continue
		}
		// zip 头里声明的解压体积可先廉价挡一刀；真正的边界仍靠 LimitReader，不信任该值。
		if f.UncompressedSize64 > uint64(entryMax) {
			return count, fmt.Errorf("native 条目 %s 声明体积超过单文件上限", f.Name)
		}
		if total >= totalMax || total+int64(f.UncompressedSize64) > totalMax {
			return count, fmt.Errorf("native 解压总量超过 %d 字节上限，疑似 zip 炸弹", totalMax)
		}
		fileName := filepath.Base(f.Name)
		destPath := filepath.Join(destDir, fileName)
		if state := inspectRegularFile(destPath); state.trustable() && state.Size == f.FileInfo().Size() {
			count++
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		limit := entryMax
		if remain := totalMax - total; remain < limit {
			limit = remain
		}
		n, streamErr := secureStreamToFile(rc, destPath, privateFilePerm, limit)
		rc.Close()
		if streamErr != nil {
			if n > limit {
				if limit < entryMax {
					return count, fmt.Errorf("native 解压总量超过 %d 字节上限，疑似 zip 炸弹", totalMax)
				}
				return count, fmt.Errorf("native 条目 %s 解压后超过单文件上限", fileName)
			}
			continue
		}
		total += n
		count++
	}
	return count, nil
}
