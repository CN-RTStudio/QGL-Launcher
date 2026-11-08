package main

// modsaudit.go —— mods 目录完整性审计内核。
//
// 背景：
//   启动器经手的 jar（在线下载、导入复制）都有静态扫描与哈希白名单保护；但用户完全
//   可能用手拖 / 压缩包解压 / 别的启动器往 mods 目录塞文件，这类“没经过哈希与扫描
//   通道”的文件在下次启动时仍会被 Mod 加载器加载。此前只有存量静态扫描
//   （moddirscan / jarscan / log4shell），缺一道“目录级完整性账本”：把 mods 目录里
//   所有普通文件的位置 / 体积 / 哈希记成基线，之后随时可对账，检出新增、缺失与被
//   篡改的文件，并按风险分级提示。
//
// 设计要点：
//   - 只读、不执行、不解压；对每个文件流式算 UMFS（本地用途哈希，遵守“本地哈希用
//     UMFS”约定），绝不同时把整个文件读进内存；
//   - 扫描有界：条目数 / 单文件体积 / 总体积三道上限，防“恶意塞满目录 -> 审计把
//     启动拖死 / 把磁盘读爆”的本地 DoS；
//   - 非普通文件（符号链接 / 设备 / 管道）一律跳过并计数，防审计被链接指向的敏感
//     外部文件带偏；目录递归只走一层子目录（mods 常见布局是“文件平铺 + 少量子
//     目录”），子目录内条目同样受总数上界约束；
//   - 基线落盘走 writePrivateJSONBounded（0600 原子写），读取走 readLocalJSONBounded
//     有界读 + 逐字段净化：相对路径必须安全（拒绝绝对路径 / ".." / 控制字符 / 超
//     长），哈希必须是 64 位十六进制，任何脏条目整体丢弃，绝不半信任恢复；
//   - 对账结果分四类：新增（基线没有 -> 未经验证来源，风险提示）、缺失（基线有但
//     已不在 -> 可能是用户删了，也可能是被整目录替换）、篡改（同名且体积变化或
//     哈希不一致 -> 最高风险，可能被恶意改写）、一致。分类结果只做上报与审计事件，
//     不自动删文件——删 mods 由用户决定。

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// mods 审计的资源上界。
const (
	modAuditMaxEntriesDefault = 4000             // 单目录条目数（含一层子目录）上界
	modAuditMaxEntryBytesDef  = int64(256) << 20 // 单文件流式哈希体积上界
	modAuditMaxTotalBytesDef  = int64(4) << 30   // 单目录审计总体积上界
	modAuditMaxSubdirs        = 32               // 一层子目录数量上界
	modAuditRelPathMaxLen     = 512              // 账本内相对路径长度上界
	modAuditBaselineVersion   = 1                // 账本格式版本
)

// ModAuditLimits 是一次 mods 审计允许消耗的资源上限。
type ModAuditLimits struct {
	MaxEntries    int
	MaxEntryBytes int64
	MaxTotalBytes int64
}

func defaultModAuditLimits() ModAuditLimits {
	return ModAuditLimits{
		MaxEntries:    modAuditMaxEntriesDefault,
		MaxEntryBytes: modAuditMaxEntryBytesDef,
		MaxTotalBytes: modAuditMaxTotalBytesDef,
	}
}

// ModAuditEntry 是账本里一个文件的记录。RelPath 相对 mods 根，使用正斜杠分隔，
// 保证跨平台可移植。
type ModAuditEntry struct {
	RelPath string `json:"relPath"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	UMFS    string `json:"umfs"`
	ModTime string `json:"modTime,omitempty"`
}

// ModAuditDir 是某个 mods 目录在账本里的快照。
type ModAuditDir struct {
	Dir     string          `json:"dir"` // 仅目录名（最后一段），不含绝对路径
	Entries []ModAuditEntry `json:"entries"`
}

// ModAuditSnapshot 是一次完整基线账本。
type ModAuditSnapshot struct {
	Version   int           `json:"version"`
	CreatedAt string        `json:"createdAt"`
	Dirs      []ModAuditDir `json:"dirs"`
}

// ModAuditDelta 描述对账时发现的一个差异条目。
type ModAuditDelta struct {
	Dir      string `json:"dir"`
	RelPath  string `json:"relPath"`
	Name     string `json:"name"`
	Kind     string `json:"kind"` // added / missing / tampered
	Baseline int64  `json:"baselineSize,omitempty"`
	Current  int64  `json:"currentSize,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// ModAuditReport 是一次对账的汇总，供前端安全页 / 手动体检消费。
type ModAuditReport struct {
	Total      int             `json:"total"`
	Added      []ModAuditDelta `json:"added"`
	Missing    []ModAuditDelta `json:"missing"`
	Tampered   []ModAuditDelta `json:"tampered"`
	Consistent int             `json:"consistent"`
	Skipped    int             `json:"skipped"` // 非普通文件 / 超限条目
	LimitHit   bool            `json:"limitHit"`
	HasRisks   bool            `json:"hasRisks"`
	Error      string          `json:"error,omitempty"`
}

// ---- 安全净化 ----

// modAuditSafeRelPath 判断账本里的相对路径是否可接受：非空、不超长、不含控制字符、
// 不是绝对路径、不含 ".." 段、不用反斜杠（账本统一正斜杠）。
func modAuditSafeRelPath(p string) bool {
	if p == "" || len(p) > modAuditRelPathMaxLen {
		return false
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") {
		return false
	}
	if strings.Contains(p, "\\") {
		return false
	}
	if hasControlCharStr(p) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// hasControlCharStr 判断字符串是否含 ASCII 控制字符（与 nameguard 口径一致）。
func hasControlCharStr(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x1F || s[i] == 0x7F {
			return true
		}
	}
	return false
}

// isValidUMFSHex 判断账本里的哈希是否 64 位小写十六进制（UMFS 输出 32 字节）。
func isValidUMFSHex(s string) bool {
	// UMFS hexdigest 只产出小写十六进制；不能用 hex.DecodeString（它会放行大写
	// A-F），否则同一内容可写入大小写两种哈希串，绕过账本的规范化去重。
	return IsLowerHex(s, 64)
}

// sanitizeModAuditEntry 逐字段净化账本条目；任何字段非法即整体丢弃（返回 false）。
func sanitizeModAuditEntry(raw *ModAuditEntry) bool {
	if raw == nil {
		return false
	}
	if !modAuditSafeRelPath(raw.RelPath) {
		return false
	}
	name := filepath.Base(strings.ReplaceAll(raw.RelPath, "/", string(filepath.Separator)))
	if name == "" || hasControlCharStr(name) || len(name) > 256 {
		return false
	}
	if raw.Size < 0 {
		return false
	}
	if !isValidUMFSHex(raw.UMFS) {
		return false
	}
	if raw.ModTime != "" && len(raw.ModTime) > 64 {
		return false
	}
	raw.Name = name
	return true
}

// ---- 目录扫描 ----

// listModAuditFiles 平铺列出 mods 目录下（含一层子目录）的普通文件相对路径，跳过
// 符号链接 / 设备 / 管道等特殊条目，并受条目数与子目录数上界约束。返回相对路径
// 列表（正斜杠）、跳过计数、是否触及上限。
func listModAuditFiles(dir string, lim ModAuditLimits) ([]string, int, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, false
	}
	relPaths := []string{}
	skipped := 0
	limitHit := false
	subdirCount := 0
	for _, e := range entries {
		if len(relPaths) >= lim.MaxEntries {
			limitHit = true
			skipped++
			continue
		}
		full := filepath.Join(dir, e.Name())
		if e.IsDir() {
			// 符号链接指向目录时 e.IsDir() 为 false，已被特殊项跳过；此处是真目录。
			if subdirCount >= modAuditMaxSubdirs {
				limitHit = true
				skipped++
				continue
			}
			subdirCount++
			sub, err := os.ReadDir(full)
			if err != nil {
				skipped++
				continue
			}
			for _, se := range sub {
				if len(relPaths) >= lim.MaxEntries {
					limitHit = true
					skipped++
					continue
				}
				if se.IsDir() {
					continue // 只下一层，更深的子目录不进账本（属扫描范围边界，不计跳过）
				}
				subFull := filepath.Join(full, se.Name())
				if bad, e2 := isSymlinkOrSpecial(subFull); e2 != nil || bad {
					skipped++
					continue
				}
				relPaths = append(relPaths,
					filepath.ToSlash(filepath.Join(e.Name(), se.Name())))
			}
			continue
		}
		if bad, e2 := isSymlinkOrSpecial(full); e2 != nil || bad {
			skipped++
			continue
		}
		relPaths = append(relPaths, filepath.ToSlash(e.Name()))
	}
	sort.Strings(relPaths)
	return relPaths, skipped, limitHit
}

// modAuditFileDigest 流式计算文件的 UMFS 摘要；超过单文件上界时返回 errLocalFileTooLarge。
func modAuditFileDigest(path string, maxBytes int64) (string, int64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", 0, err
	}
	if maxBytes > 0 && fi.Size() > maxBytes {
		return "", fi.Size(), errLocalFileTooLarge
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := NewUMFSHash()
	written, err := io.Copy(h, io.LimitReader(f, maxBytes+1))
	if err != nil {
		return "", 0, err
	}
	if maxBytes > 0 && written > maxBytes {
		return "", written, errLocalFileTooLarge
	}
	return hex.EncodeToString(h.Sum(nil)), written, nil
}

// collectModAuditDir 为一个 mods 目录生成账本快照。返回条目、跳过数、是否触及上限。
func collectModAuditDir(dir string, lim ModAuditLimits) ([]ModAuditEntry, int, bool, error) {
	relPaths, skipped, limitHit := listModAuditFiles(dir, lim)
	entries := make([]ModAuditEntry, 0, len(relPaths))
	var total int64
	for _, rel := range relPaths {
		if int64(len(entries)) >= int64(lim.MaxEntries) {
			limitHit = true
			skipped++
			break
		}
		full := filepath.Join(dir, filepath.FromSlash(rel))
		sum, size, err := modAuditFileDigest(full, lim.MaxEntryBytes)
		if err != nil {
			if errors.Is(err, errLocalFileTooLarge) {
				limitHit = true
				skipped++
				continue
			}
			skipped++
			continue
		}
		if lim.MaxTotalBytes > 0 && total+size > lim.MaxTotalBytes {
			limitHit = true
			skipped++
			continue
		}
		total += size
		entry := ModAuditEntry{
			RelPath: rel,
			Name:    filepath.Base(rel),
			Size:    size,
			UMFS:    sum,
		}
		if fi, e2 := os.Stat(full); e2 == nil {
			entry.ModTime = fi.ModTime().UTC().Format(time.RFC3339)
		}
		entries = append(entries, entry)
	}
	return entries, skipped, limitHit, nil
}

// ---- 基线读写 ----

// buildModAuditSnapshot 为多个 mods 目录生成一张基线账本。dirs 为目录名（非绝对
// 路径），absRoots 与之对齐的绝对根。
func buildModAuditSnapshot(absRoots []string, lim ModAuditLimits) (*ModAuditSnapshot, int, bool, error) {
	snap := &ModAuditSnapshot{
		Version:   modAuditBaselineVersion,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Dirs:      []ModAuditDir{},
	}
	totalSkipped := 0
	anyLimit := false
	for _, abs := range absRoots {
		if abs == "" {
			continue
		}
		entries, skipped, limitHit, err := collectModAuditDir(abs, lim)
		totalSkipped += skipped
		if limitHit {
			anyLimit = true
		}
		if err != nil {
			continue
		}
		if len(entries) == 0 {
			continue
		}
		snap.Dirs = append(snap.Dirs, ModAuditDir{
			Dir:     filepath.Base(abs),
			Entries: entries,
		})
	}
	return snap, totalSkipped, anyLimit, nil
}

// loadModAuditSnapshot 有界读 + 逐字段净化基线账本。文件不存在返回 nil（首次基线）。
func loadModAuditSnapshot(path string) (*ModAuditSnapshot, error) {
	raw := &ModAuditSnapshot{}
	if err := readLocalJSONBounded(path, raw, 16<<20, "mods 审计基线"); err != nil {
		if os.IsNotExist(err) || errors.Is(err, errLocalFileTooLarge) {
			return nil, nil
		}
		return nil, err
	}
	if raw.Version != modAuditBaselineVersion {
		return nil, fmt.Errorf("mods 审计基线版本不兼容")
	}
	out := &ModAuditSnapshot{Version: raw.Version, CreatedAt: raw.CreatedAt, Dirs: []ModAuditDir{}}
	for _, d := range raw.Dirs {
		if !modAuditSafeRelPath(d.Dir) {
			continue
		}
		clean := ModAuditDir{Dir: d.Dir, Entries: []ModAuditEntry{}}
		for _, e := range d.Entries {
			cp := e
			if sanitizeModAuditEntry(&cp) {
				clean.Entries = append(clean.Entries, cp)
			}
		}
		if len(clean.Entries) > 0 {
			out.Dirs = append(out.Dirs, clean)
		}
	}
	return out, nil
}

// saveModAuditSnapshot 原子私有写基线账本（0600）。
func saveModAuditSnapshot(path string, snap *ModAuditSnapshot) error {
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	return writePrivateJSONBounded(path, snap, 16<<20)
}

// ---- 对账 ----

// auditModsAgainstBaseline 把当前 mods 目录与基线账本对账，产出差异报告。
// current 为当前快照；baseline 可为 nil（无基线 -> 全量视为新增）。
func auditModsAgainstBaseline(current *ModAuditSnapshot, baseline *ModAuditSnapshot) ModAuditReport {
	report := ModAuditReport{
		Added:    []ModAuditDelta{},
		Missing:  []ModAuditDelta{},
		Tampered: []ModAuditDelta{},
	}
	if current == nil {
		return report
	}
	byDir := map[string]map[string]ModAuditEntry{}
	baseByDir := map[string]map[string]ModAuditEntry{}
	for _, d := range current.Dirs {
		byDir[d.Dir] = map[string]ModAuditEntry{}
		for _, e := range d.Entries {
			byDir[d.Dir][e.RelPath] = e
		}
		report.Total += len(d.Entries)
	}
	if baseline != nil {
		for _, d := range baseline.Dirs {
			baseByDir[d.Dir] = map[string]ModAuditEntry{}
			for _, e := range d.Entries {
				baseByDir[d.Dir][e.RelPath] = e
			}
		}
	}
	dirNames := []string{}
	seen := map[string]bool{}
	for name := range byDir {
		if !seen[name] {
			seen[name] = true
			dirNames = append(dirNames, name)
		}
	}
	for name := range baseByDir {
		if !seen[name] {
			seen[name] = true
			dirNames = append(dirNames, name)
		}
	}
	sort.Strings(dirNames)

	for _, dirName := range dirNames {
		cur := byDir[dirName]
		base := baseByDir[dirName]
		for rel, e := range cur {
			b, ok := base[rel]
			if !ok {
				report.Added = append(report.Added, ModAuditDelta{
					Dir: dirName, RelPath: rel, Name: e.Name, Kind: "added",
					Current: e.Size, Detail: "基线中没有该文件，来源未经验证",
				})
				continue
			}
			if b.Size != e.Size || b.UMFS != e.UMFS {
				report.Tampered = append(report.Tampered, ModAuditDelta{
					Dir: dirName, RelPath: rel, Name: e.Name, Kind: "tampered",
					Baseline: b.Size, Current: e.Size,
					Detail: "文件体积或哈希与基线不一致，可能被改写",
				})
				continue
			}
			report.Consistent++
		}
		for rel, b := range base {
			if _, ok := cur[rel]; !ok {
				report.Missing = append(report.Missing, ModAuditDelta{
					Dir: dirName, RelPath: rel, Name: b.Name, Kind: "missing",
					Baseline: b.Size, Detail: "基线中存在但当前目录已缺失",
				})
			}
		}
	}
	report.HasRisks = len(report.Added) > 0 || len(report.Missing) > 0 || len(report.Tampered) > 0
	return report
}

// modAuditSummaryText 生成一段给审计事件用的中文摘要。
func modAuditSummaryText(r ModAuditReport) string {
	var parts []string
	if len(r.Tampered) > 0 {
		parts = append(parts, fmt.Sprintf("篡改 %d", len(r.Tampered)))
	}
	if len(r.Added) > 0 {
		parts = append(parts, fmt.Sprintf("新增 %d", len(r.Added)))
	}
	if len(r.Missing) > 0 {
		parts = append(parts, fmt.Sprintf("缺失 %d", len(r.Missing)))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("mods 目录完整性一致（%d 个文件）", r.Total)
	}
	return "mods 目录完整性异常: " + strings.Join(parts, "、") +
		fmt.Sprintf("（共 %d 个文件）", r.Total)
}
