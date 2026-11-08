package main

// envbudget：启动环境变量总量预算守卫。
//
// 场景：启动器把实例配置里的环境变量原样透传给 Java 子进程。攻击者可以
// 塞入成百上千条 / 超长环境变量（环境块上限 ~32KB 或更多），在 exec 前
// 耗尽内存、或让 CreateProcess/exec 直接失败，形成本地 DoS；某些启动器
// 还会把环境变量内容拼进日志（日志注入）。本模块：
//   - 对「启动器侧」的环境变量集合做总量预算：条数上限 + 总字节上限 +
//     单条键/值长度上限 + 总条数上限；
//   - 键名校验：只允许 [A-Za-z_][A-Za-z0-9_]*，拒绝 PATH 类危险键被覆盖
//     （黑名单键：PATH/PATHEXT/LD_PRELOAD/LD_LIBRARY_PATH/DYLD_* 等，
//     覆盖这些键等价于改子进程加载路径）；
//   - 值校验：剔除 NUL 与控制字符（Windows env 不允许 = 号出现在键里、
//     NUL 分隔符不允许出现在值里）；
//   - 纯函数，只返回 verdict 与净化建议，不改任何配置。

import (
	"strings"
)

// EnvLimits 环境变量预算的量化边界。
type EnvLimits struct {
	MaxEntries  int
	MaxTotalKB  int
	MaxKeyLen   int
	MaxValueLen int
}

func defaultEnvLimits() EnvLimits {
	return EnvLimits{
		MaxEntries:  128,
		MaxTotalKB:  16,
		MaxKeyLen:   128,
		MaxValueLen: 4096,
	}
}

// 覆盖这些键会重写子进程的加载/查找路径，视为高危。
var envBlockedKeys = []string{
	"PATH", "PATHEXT", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
	"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
	"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS",
}

type envEntry struct {
	Key string
	Val string
}

type envVerdict struct {
	OK        bool
	Reason    string
	Entries   []envEntry
	TotalKB   int
	BlockedAt []string
}

// envKeyOK 键名只允许常规环境变量字符集。
func envKeyOK(key string, lim EnvLimits) bool {
	if key == "" || len(key) > lim.MaxKeyLen {
		return false
	}
	for i, r := range key {
		ok := r == '_' ||
			(r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(i > 0 && r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// envValueOK 剔除 NUL/控制字符（含 CR/LF，防日志注入与参数拼接绕过）。
func envValueOK(val string, lim EnvLimits) bool {
	if len(val) > lim.MaxValueLen {
		return false
	}
	if strings.IndexByte(val, 0) >= 0 {
		return false
	}
	for _, r := range val {
		if r < 32 && r != 9 {
			return false
		}
	}
	return true
}

func envKeyBlocked(key string) bool {
	upper := strings.ToUpper(key)
	for _, b := range envBlockedKeys {
		if upper == b {
			return true
		}
	}
	return false
}

// AuditEnvBudget 对启动器透传前的环境变量集合做总量/键/值校验。
// 返回 verdict：OK=false 时 Reason 说明首个违规；Entries 只含通过校验项；
// BlockedAt 列出被拒绝的危险键名（供日志展示，不含值）。
func AuditEnvBudget(env []string, lim EnvLimits) envVerdict {
	if lim.MaxEntries == 0 || lim.MaxTotalKB == 0 {
		lim = defaultEnvLimits()
	}
	v := envVerdict{OK: true}
	total := 0
	for _, item := range env {
		eq := strings.IndexByte(item, '=')
		if eq <= 0 {
			v.OK = false
			v.Reason = "bad-entry"
			return v
		}
		key := item[:eq]
		val := item[eq+1:]
		if !envKeyOK(key, lim) {
			v.OK = false
			v.Reason = "bad-key"
			return v
		}
		if envKeyBlocked(key) {
			v.BlockedAt = append(v.BlockedAt, key)
			v.OK = false
			v.Reason = "blocked-key:" + key
			return v
		}
		if !envValueOK(val, lim) {
			v.OK = false
			v.Reason = "bad-value"
			return v
		}
		if len(v.Entries) >= lim.MaxEntries {
			v.OK = false
			v.Reason = "too-many-entries"
			return v
		}
		total += len(item)
		if total > lim.MaxTotalKB<<10 {
			v.OK = false
			v.Reason = "too-large-env"
			return v
		}
		v.Entries = append(v.Entries, envEntry{Key: key, Val: val})
	}
	v.TotalKB = total >> 10
	return v
}

// SummarizeEnvVerdict 压成一行结果；BlockedAt 只列键名不列值。
func SummarizeEnvVerdict(v envVerdict) string {
	status := "ok"
	if !v.OK {
		status = "blocked:" + v.Reason
	}
	extra := ""
	if len(v.BlockedAt) > 0 {
		extra = " blocked=" + strings.Join(v.BlockedAt, ",")
	}
	return "envbudget: " + status + " entries=" + itoaSafe(len(v.Entries)) + extra
}
