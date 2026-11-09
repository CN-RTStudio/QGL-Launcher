package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// extractNativesWithLimits 是真正的解压内核，单文件 / 总量上限由调用方传入，
// 既让生产路径用固定安全常量，也便于用小阈值对体积边界做轻量单测（不必造几百 MiB 数据）。
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
		if err := os.MkdirAll(destDir, 0700); err != nil {
			rc.Close()
			return count, fmt.Errorf("创建 natives 目录失败: %v", err)
		}
		// 先写到同目录临时文件，完整通过体积校验后再原子替换，避免留下半截大文件。
		tmp, err := os.CreateTemp(destDir, ".native-*.tmp")
		if err != nil {
			rc.Close()
			continue
		}
		tmpName := tmp.Name()
		limited := io.LimitReader(rc, entryMax+1)
		n, copyErr := io.Copy(tmp, limited)
		tmp.Close()
		rc.Close()
		if copyErr != nil {
			os.Remove(tmpName)
			continue
		}
		if n > entryMax || total+n > totalMax {
			os.Remove(tmpName)
			if n > entryMax {
				return count, fmt.Errorf("native 条目 %s 解压后超过单文件上限", fileName)
			}
			return count, fmt.Errorf("native 解压总量超过 %d 字节上限，疑似 zip 炸弹", totalMax)
		}
		if err := os.Chmod(tmpName, 0600); err != nil {
			os.Remove(tmpName)
			continue
		}
		if err := os.Rename(tmpName, destPath); err != nil {
			os.Remove(tmpName)
			continue
		}
		total += n
		count++
	}
	return count, nil
}

func (a *App) extractNativesFromJSON(mcDir string, nativesDir string, versionJSON *VersionJSON) {
	// 解压根目录统一收权到 0700（历史上若存在 0755 的 natives 目录会被原样沿用）。
	_ = ensurePrivateDir(nativesDir)
	for _, lib := range versionJSON.Libraries {
		if lib.Natives == nil {
			continue
		}
		// 与下载阶段使用同一套“按真实架构选 Windows natives 键 + ${arch} 替换”
		// 的规则，避免下载和解压挑到不同分类器（旧实现这里只看 windows-64/windows）。
		winEnv := ruleEnv{osName: "windows", osArch: currentRuleEnv().osArch}
		nativeKey, hasNative := resolveWindowsNativeKey(lib.Natives, winEnv)
		if !hasNative {
			continue
		}
		if lib.Downloads == nil || lib.Downloads.Classifiers == nil {
			continue
		}
		classifier, ok := lib.Downloads.Classifiers[nativeKey]
		if !ok || classifier == nil {
			continue
		}
		// 与下载阶段一致，这里必须再次校验 classifier.Path：版本 JSON 来自镜像
		// 站（不可信），而本函数也会被非 DownloadVersion 的其它启动流程调用。
		safeClassifierPath := isSafeRelPath(classifier.Path)
		if safeClassifierPath == "" {
			a.writeLog("跳过不安全的 native jar 路径: %s", classifier.Path)
			continue
		}
		nativeJarPath := filepath.Join(mcDir, "libraries", safeClassifierPath)
		if !inspectRegularFile(nativeJarPath).trustable() {
			a.writeLog("native jar 不存在(跳过): %s", nativeJarPath)
			continue
		}
		extracted, err := extractNatives(nativeJarPath, nativesDir)
		if err != nil {
			a.writeLog("解压 native 失败: %s, %v", classifier.Path, err)
		} else if extracted > 0 {
			a.writeLog("解压 native: %s -> %d 个文件", classifier.Path, extracted)
		}
	}
}

func isDirEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true, err
	}
	return len(entries) == 0, nil
}

const maxCopyDirEntryBytes int64 = 256 << 20

func copyDirContents(srcDir string, dstDir string) error {
	if err := os.MkdirAll(dstDir, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	var total int64
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// ReadDir 不跟随链接：任何非常规文件（符号链接 / 设备 / 管道等）一律跳过。
		if entry.Type()&os.ModeType != 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		size := info.Size()
		if size > maxCopyDirEntryBytes || total+size > maxNativeTotalBytes {
			continue
		}
		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())
		// copyFileSecure 内部会再做一次源链接检查、目标链接拒绝，并以 LimitReader
		// 多读 1 字节发现“声明大小正常但读取中持续增长”的文件。
		if err := copyFileSecure(srcPath, dstPath, 0600, maxCopyDirEntryBytes); err != nil {
			continue
		}
		total += size
	}
	return nil
}
