package main

// crashreport：崩溃报告守卫。
//
// 场景：崩溃后启动器会列出 crash-reports/ 下的报告供用户查看/上传。伪造或
// 被污染的报告文件（巨型文件、畸形文件名、内含 access token / 邮箱明文）
// 会让启动器 UI 卡死、日志注入或在“一键反馈”时把敏感凭据发出去。本模块：
//   - 报告文件名结构校验（crash-<时间戳>.txt / hs_err_pid<pid>.log 形态，
//     拒绝穿越与控制字符）；
//   - 单个报告文件大小上限，超大文件标记为不可直接打开；
//   - 内容敏感扫描：检测疑似 accessToken / 邮箱 / 令牌行，返回行号供脱敏；
//   - 报告数量上限：只保留最近 N 份（由调用方决定是否清理，本模块只统计）。

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// CrashLimits 崩溃报告守卫的量化边界。
type CrashLimits struct {
	MaxReportBytes int64 // 单份报告上限（超限标记，不截断）
	MaxReports     int   // 目录内报告数量上限
	MaxScanLines   int   // 内容扫描行数上限
}

func defaultCrashLimits() CrashLimits {
	return CrashLimits{MaxReportBytes: 16 << 20, MaxReports: 200, MaxScanLines: 20000}
}

// crashReportInfo 单份报告的判定结果。
type crashReportInfo struct {
	Name     string
	Path     string
	Kind     string // "crash-report" / "hs-err" / "unknown"
	TooLarge bool
	Sensitive []string // 敏感行（已脱敏类别 + 行号）
}

type crashVerdict struct {
	OK      bool
	Reason  string
	Reports []crashReportInfo
	Count   int
}

// classifyCrashName 分类报告文件名。
func classifyCrashName(name string) (kind string, ok bool) {
	if name == "" || len(name) > 255 {
		return "", false
	}
	if hasControlCharStr(name) || strings.ContainsAny(name, "/\\") {
		return "", false
	}
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, "crash-") && strings.HasSuffix(lower, ".txt"):
		return "crash-report", true
	case strings.HasPrefix(lower, "hs_err_pid") && strings.HasSuffix(lower, ".log"):
		return "hs-err", true
	default:
		return "unknown", false
	}
}

// scanCrashSensitive 扫描报告内容的敏感行。返回行号（1-based）与类别。
// 只做脱敏提示，不读取令牌明文（不把凭据带出扫描函数）。
func scanCrashSensitive(r ioReaderAt, size int64, maxScan int) []string {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	lineNo := 0
	reToken := regexp.MustCompile(`(?i)(access[_-]?token|accessToken|refresh[_-]?token|authToken)["' :=]{1,3}([0-9a-f]{16,})`)
	reEmail := regexp.MustCompile(`(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`)
	reMCUUID := regexp.MustCompile(`(?i)uuid["' :=]{1,3}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	var hits []string
	for sc.Scan() && lineNo < maxScan {
		lineNo++
		line := sc.Text()
		if len(line) > 4096 {
			continue
		}
		switch {
		case reToken.MatchString(line):
			hits = append(hits, "token:"+itoaSafe(lineNo))
		case reMCUUID.MatchString(line):
			hits = append(hits, "uuid:"+itoaSafe(lineNo))
		case reEmail.MatchString(line):
			hits = append(hits, "email:"+itoaSafe(lineNo))
		}
		if len(hits) >= 20 {
			break
		}
	}
	return hits
}

type ioReaderAt interface {
	Read(p []byte) (n int, err error)
}

// inspectCrashFile 检查单个报告文件。
func inspectCrashFile(p string, lim CrashLimits) crashReportInfo {
	info := crashReportInfo{Name: filepath.Base(p), Path: p}
	kind, ok := classifyCrashName(info.Name)
	if !ok {
		info.Kind = "unknown"
		return info
	}
	info.Kind = kind
	fi, err := os.Stat(p)
	if err != nil {
		info.Kind = "missing"
		return info
	}
	if fi.Size() > lim.MaxReportBytes {
		info.TooLarge = true
		return info
	}
	f, err := os.Open(p)
	if err != nil {
		return info
	}
	defer f.Close()
	info.Sensitive = scanCrashSensitive(f, fi.Size(), lim.MaxScanLines)
	return info
}

// ScanCrashDir 扫描崩溃报告目录。
func ScanCrashDir(dir string, lim CrashLimits) crashVerdict {
	if lim.MaxReportBytes == 0 {
		lim = defaultCrashLimits()
	}
	vd := crashVerdict{OK: true}
	entries, err := os.ReadDir(dir)
	if err != nil {
		vd.OK = false
		vd.Reason = "readdir-fail"
		return vd
	}
	var reports []crashReportInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if e.Type()&os.ModeSymlink != 0 {
			vd.OK = false
			vd.Reason = "symlink-entry"
			return vd
		}
		full := filepath.Join(dir, e.Name())
		info := inspectCrashFile(full, lim)
		if info.Kind == "unknown" {
			continue // 非报告文件不归入
		}
		reports = append(reports, info)
	}
	vd.Reports = reports
	vd.Count = len(reports)
	if vd.Count > lim.MaxReports {
		vd.OK = false
		vd.Reason = "reports-overflow"
		return vd
	}
	for _, r := range reports {
		if r.TooLarge || len(r.Sensitive) > 0 {
			vd.OK = false
			if r.TooLarge {
				vd.Reason = "report-too-large:" + r.Name
			} else {
				vd.Reason = "report-sensitive:" + r.Name
			}
			return vd
		}
	}
	return vd
}

// SummarizeCrashVerdict 压成一行。
func SummarizeCrashVerdict(vd crashVerdict) string {
	if vd.OK {
		return "crashreports ok count=" + itoaSafe(vd.Count)
	}
	return "crashreports bad " + vd.Reason
}
