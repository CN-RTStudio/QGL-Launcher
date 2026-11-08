package main

// nativelibs：本地库目录守卫。
//
// 场景：LWJGL natives 解压到 natives/<hash>/ 后，启动时会把该目录加入
// java.library.path。被篡改的 natives 目录若含非库文件（如批处理 / 脚本 /
// 符号链接指向系统 DLL），或文件名含穿越成分，可能造成 DLL 劫持或启动
// 命令行注入。本模块：
//   - 目录遍历：只接受 .dll / .so / .dylib / .json / .txt（描述文件），
//     其余扩展名一律拒绝；
//   - 文件名：无路径分隔符 / 控制字符 / 前缀点，长度有界；
//   - 拒绝符号链接（防指向任意系统库）；
//   - 文件数量与总大小有界（防解压炸弹）。

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// NativeLimits 本地库目录守卫的量化边界。
type NativeLimits struct {
	MaxEntries int
	MaxBytes   int64
	MaxNameLen int
}

var errStopNative = errors.New("scan-stop")

func defaultNativeLimits() NativeLimits {
	return NativeLimits{MaxEntries: 20000, MaxBytes: 4 << 30, MaxNameLen: 255}
}

type nativeEntry struct {
	Name string
	Size int64
}

type nativeVerdict struct {
	OK      bool
	Reason  string
	Entries []nativeEntry
}

// nativeExtOK 允许的 natives 文件扩展名。
func nativeExtOK(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".dll") || strings.HasSuffix(lower, ".so") ||
		strings.HasSuffix(lower, ".dylib") || strings.HasSuffix(lower, ".json") ||
		strings.HasSuffix(lower, ".txt")
}

// ScanNativesDir 扫描 natives 目录。
func ScanNativesDir(dir string, lim NativeLimits) nativeVerdict {
	if lim.MaxEntries == 0 {
		lim = defaultNativeLimits()
	}
	vd := nativeVerdict{OK: true}
	entries := []nativeEntry{}
	var total int64
	err := filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if fi.IsDir() {
			return nil
		}
		name := fi.Name()
		if fi.Mode()&os.ModeSymlink != 0 {
			vd.OK = false
			vd.Reason = "symlink:" + name
			return errStopNative
		}
		if strings.HasPrefix(name, ".") {
			vd.OK = false
			vd.Reason = "hidden-file:" + name
			return errStopNative
		}
		if len(name) > lim.MaxNameLen {
			vd.OK = false
			vd.Reason = "name-too-long:" + name
			return errStopNative
		}
		if strings.ContainsAny(name, "/\\") || hasControlCharStr(name) {
			vd.OK = false
			vd.Reason = "name-illegal:" + name
			return errStopNative
		}
		if !nativeExtOK(name) {
			vd.OK = false
			vd.Reason = "ext:" + name
			return errStopNative
		}
		entries = append(entries, nativeEntry{Name: name, Size: fi.Size()})
		total += fi.Size()
		if len(entries) > lim.MaxEntries {
			vd.OK = false
			vd.Reason = "entries-overflow"
			return errStopNative
		}
		if total > lim.MaxBytes {
			vd.OK = false
			vd.Reason = "bytes-overflow"
			return errStopNative
		}
		return nil
	})
	if err == errStopNative {
		return vd
	}
	if err != nil {
		vd.OK = false
		vd.Reason = "walk-fail"
		return vd
	}
	vd.Entries = entries
	return vd
}

// SummarizeNativeVerdict 压成一行。
func SummarizeNativeVerdict(vd nativeVerdict) string {
	if vd.OK {
		return "natives ok entries=" + itoaSafe(len(vd.Entries))
	}
	return "natives bad " + vd.Reason
}
