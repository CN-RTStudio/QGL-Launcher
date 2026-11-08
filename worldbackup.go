package main

// worldbackup.go —— 世界存档安全备份 / 恢复内核。
//
// 这是启动器该有、此前却完全缺失的一道“防丢档”能力：玩家一个世界可能玩了几百
// 小时，一次误删 / 磁盘损坏 / 版本升级存档格式不兼容都会不可逆地丢掉。本模块在
// “受信根 + 体量预算 + 原子落盘 + 清单校验”的既有安全框架内实现本地世界备份：
//
//   - 备份源只能是 <gameDir>/saves/<worldName>：gameDir 必须落在 .minecraft 之内，
//     worldName 过 auditComponent（拒绝路径分隔符 / ".." / 控制字符 / Unicode 不可见
//     与 bidi / Windows 保留设备名），解析后再用 PathWithinRoot 双重确认，挡住链接逃逸；
//   - 打包过程只收普通文件，符号链接 / 设备 / 管道 / 套接字一律拒绝（防把 saves 里
//     预先埋好的链接所指向的外部敏感文件打进备份）；
//   - 条目数 / 单文件 / 总体积三道上限防“存档即解压炸弹”撑爆备份盘，落盘前先用
//     diskspaceguard 预留安全水位，zip 走临时文件 + fsync + rename 的原子写；
//   - 备份文件统一放在 QGL/worldbackups/<world>/ 下，与游戏目录隔离；每个 zip 旁写
//     一份 0600 清单，记录条目数 / 体积 / UMFS 摘要，恢复前强制核对摘要；
//   - 恢复绝不覆盖任何已有目录：总是解压到 saves/<world>-restored-<stamp> 新目录，并
//     复用 zipextract 的 Zip Slip / 特殊条目 / 炸弹防护（空前缀=整包相对路径）。
//
// 这里的 UMFS 仅用于“本地备份完整性”用途，符合“本地用途哈希用 UMFS”的约定；
// 不涉及任何外部下载 API 的 SHA1 / SHA256 校验算法。

import (
	"archive/zip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	worldBackupRootFolder = "worldbackups"
	worldSavesFolder      = "saves"

	maxWorldNameLen = 64

	// 单世界备份的体量预算。默认值刻意覆盖主流整合包存档（通常 < 1GiB），但用
	// 明确的天花板封死“存档目录被塞几百 GB 文件 -> 备份把盘写满”的本地 DoS。
	worldKeepDefault = 8
	worldKeepMax     = 32

	worldMaxEntriesDefault = 20000
	worldMaxEntriesCeiling = 100000
	worldMaxTotalDefault   = int64(2) << 30 // 2GiB
	worldMaxTotalCeiling   = int64(8) << 30 // 8GiB
	worldMaxEntryDefault   = int64(256) << 20
	worldMaxEntryCeiling   = int64(1) << 30

	// 备份落盘除了数据本身外，额外为 zip 临时膨胀 / 目录元数据预留的安全余量。
	worldReserveHeadroom = int64(256) << 20

	worldStampLayout = "20060102-150405"
	worldStampLen    = 15
)

// WorldBackupLimits 是一次世界备份 / 恢复允许消耗的资源上限。
type WorldBackupLimits struct {
	MaxEntries    int   // 普通文件条目数上限
	MaxTotalBytes int64 // 全部文件合计字节上限
	MaxEntryBytes int64 // 单个文件字节上限
	Keep          int   // 每个世界保留的备份份数（超出按时间淘汰最旧）
}

func defaultWorldBackupLimits() WorldBackupLimits {
	return WorldBackupLimits{
		MaxEntries:    worldMaxEntriesDefault,
		MaxTotalBytes: worldMaxTotalDefault,
		MaxEntryBytes: worldMaxEntryDefault,
		Keep:          worldKeepDefault,
	}
}

// normalizeWorldBackupLimits 把外部传入 / 缺省的上限收敛到合法区间。零值取默认，
// 负值折叠为 0 再取默认，任何高于天花板的值压回天花板——调用方无法借自定义上限
// 绕过磁盘 DoS 防护。
func normalizeWorldBackupLimits(l WorldBackupLimits) WorldBackupLimits {
	n := defaultWorldBackupLimits()
	if l.MaxEntries > 0 {
		n.MaxEntries = l.MaxEntries
	}
	if l.MaxTotalBytes > 0 {
		n.MaxTotalBytes = l.MaxTotalBytes
	}
	if l.MaxEntryBytes > 0 {
		n.MaxEntryBytes = l.MaxEntryBytes
	}
	if l.Keep > 0 {
		n.Keep = l.Keep
	}
	if n.MaxEntries > worldMaxEntriesCeiling {
		n.MaxEntries = worldMaxEntriesCeiling
	}
	if n.MaxTotalBytes > worldMaxTotalCeiling {
		n.MaxTotalBytes = worldMaxTotalCeiling
	}
	if n.MaxEntryBytes > worldMaxEntryCeiling {
		n.MaxEntryBytes = worldMaxEntryCeiling
	}
	if n.Keep > worldKeepMax {
		n.Keep = worldKeepMax
	}
	if n.MaxEntryBytes > n.MaxTotalBytes {
		n.MaxEntryBytes = n.MaxTotalBytes
	}
	return n
}

// WorldInfo 是 saves 目录下一个世界目录的概要。
type WorldInfo struct {
	Name       string `json:"name"`
	Entries    int    `json:"entries"`
	TotalBytes int64  `json:"totalBytes"`
	ModTime    string `json:"modTime"`
}

// WorldBackupMeta 是单个备份 zip 旁边的清单。UMFS 字段为备份内容的本地完整性摘要。
type WorldBackupMeta struct {
	WorldName  string `json:"worldName"`
	Stamp      string `json:"stamp"`
	CreatedAt  string `json:"createdAt"`
	Entries    int    `json:"entries"`
	TotalBytes int64  `json:"totalBytes"`
	ZipName    string `json:"zipName"`
	UMFS       string `json:"umfs"`
}

// worldPlannedFile 是预检通过、等待写入 zip 的一个普通文件。
type worldPlannedFile struct {
	abs  string
	rel  string // 统一 '/' 分隔、相对世界根的路径
	size int64
}

type worldError string

func (e worldError) Error() string { return string(e) }

// validateWorldName 校验世界目录名单段，复用 nameguard 的统一落盘名审计。
func validateWorldName(name string) (string, string) {
	trimmed := strings.TrimSpace(name)
	if reason := auditComponent(trimmed, maxWorldNameLen); reason != nameRejectNone {
		return "", reason
	}
	return trimmed, nameRejectNone
}

// validateWorldStamp 校验时间戳段是规范的 20060102-150405：除字符形态外还做
// 真实日历 / 时钟范围校验并要求与规范化结果完全一致，杜绝用 13 月、40 日、99 时
// 这类“看起来像时间戳”的非法串拼路径。
func validateWorldStamp(stamp string) bool {
	if len(stamp) != worldStampLen || stamp[8] != '-' {
		return false
	}
	t, err := time.Parse(worldStampLayout, stamp)
	if err != nil {
		return false
	}
	return t.Format(worldStampLayout) == stamp
}

// resolveWorldDir 校验并返回某个世界的真实目录：必须是 saves 下的普通目录，
// 不能是符号链接 / 特殊文件，且真实路径仍在 saves 之内。
func resolveWorldDir(savesDir, worldName string) (string, error) {
	cleanName, reason := validateWorldName(worldName)
	if reason != nameRejectNone {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionRejected,
			"worldbackup", "世界名校验未通过: "+reason)
		return "", worldError("世界目录名不合法: " + reason)
	}
	worldDir := filepath.Join(savesDir, cleanName)
	// 直接 Lstat（不跟随）：世界根必须是一个真实目录；符号链接根一律拒绝，防止
	// saves 里预置链接把外部目录当成世界打包。注意不能用 isSymlinkOrSpecial——
	// 它把普通目录也归为“非常规”，会误杀所有合法世界。
	li, err := os.Lstat(worldDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", worldError("世界目录不存在")
		}
		return "", worldError("检查世界目录失败")
	}
	if li.Mode()&os.ModeSymlink != 0 {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			"worldbackup", "世界目录是符号链接，拒绝: "+cleanName)
		return "", worldError("拒绝备份符号链接形式的世界目录")
	}
	if !li.IsDir() {
		return "", worldError("目标不是世界目录")
	}
	if !PathWithinRoot(worldDir, savesDir) {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			"worldbackup", "世界真实路径越出 saves 根: "+cleanName)
		return "", worldError("世界路径越界")
	}
	return worldDir, nil
}

// planWorldFiles 遍历世界目录做只读预检：只收普通文件，逐文件 / 总量 / 条目数
// 预算全部在这里裁决，返回的计划即打包的唯一依据。
func planWorldFiles(worldDir string, lim WorldBackupLimits) ([]worldPlannedFile, int64, error) {
	planned := make([]worldPlannedFile, 0, 256)
	var total int64

	walkErr := filepath.WalkDir(worldDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == worldDir {
			return nil
		}
		rel, relErr := filepath.Rel(worldDir, path)
		if relErr != nil || strings.HasPrefix(filepath.ToSlash(rel), "../") || rel == ".." {
			recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
				"worldbackup", "世界内出现越界相对路径: "+path)
			return worldError("世界内存在越界路径")
		}
		if d.IsDir() {
			// 子目录放行继续遍历；空目录结构无需备份，文件的父目录在解包时重建。
			return nil
		}
		// 走到这里只能是普通文件：符号链接 / 设备 / 管道 / 套接字一律拒绝，
		// 绝不跟随或落地（同样不能用把目录误判为特殊的 isSymlinkOrSpecial）。
		if mode := d.Type(); mode&os.ModeSymlink != 0 || !mode.IsRegular() {
			recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
				"worldbackup", "世界内存在符号链接或特殊文件，拒绝: "+rel)
			return worldError("世界内存在不允许的链接或特殊文件")
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		size := info.Size()
		if size < 0 {
			return worldError("文件体积非法")
		}
		if size > lim.MaxEntryBytes {
			return worldError(fmt.Sprintf("世界文件 %s 体积 %d 超过单文件上限", rel, size))
		}
		if size > lim.MaxTotalBytes-total {
			return worldError("世界总体积超过备份上限")
		}
		total += size
		if len(planned) >= lim.MaxEntries {
			return worldError("世界文件条目数超过上限")
		}
		planned = append(planned, worldPlannedFile{
			abs:  path,
			rel:  filepath.ToSlash(rel),
			size: size,
		})
		return nil
	})
	if walkErr != nil {
		return nil, 0, walkErr
	}
	if len(planned) == 0 {
		return nil, 0, worldError("世界目录为空，没有可备份的文件")
	}
	return planned, total, nil
}

// writeWorldZipAtomic 按计划把世界文件流式写入目标 zip（Deflate）。临时文件 +
// fsync + rename 保证半成品永不落到最终路径；每个文件多读 1 字节以发现读取期间
// 仍在增长的文件。返回条目数与源数据合计字节。
func writeWorldZipAtomic(planned []worldPlannedFile, zipPath string, lim WorldBackupLimits) (int, int64, error) {
	dir := filepath.Dir(zipPath)
	if err := ensurePrivateDir(dir); err != nil {
		return 0, 0, err
	}
	tmp, err := os.CreateTemp(dir, ".worldbackup-*")
	if err != nil {
		return 0, 0, fmt.Errorf("创建备份临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	abort := func(cause error) (int, int64, error) {
		tmp.Close()
		os.Remove(tmpName)
		return 0, 0, cause
	}

	zw := zip.NewWriter(tmp)
	var written int64
	for i := range planned {
		f := planned[i]
		in, openErr := os.Open(f.abs)
		if openErr != nil {
			zw.Close()
			return abort(fmt.Errorf("打开世界文件失败 %s: %w", f.rel, openErr))
		}
		header := &zip.FileHeader{Name: f.rel, Method: zip.Deflate}
		header.SetMode(0o600)
		w, createErr := zw.CreateHeader(header)
		if createErr != nil {
			in.Close()
			zw.Close()
			return abort(fmt.Errorf("创建 zip 条目失败 %s: %w", f.rel, createErr))
		}
		// 多读 1 字节：若文件在规划后又被写大，立即中止而不是悄悄截断。
		n, copyErr := io.Copy(w, io.LimitReader(in, f.size+1))
		in.Close()
		if copyErr != nil {
			zw.Close()
			return abort(fmt.Errorf("读取世界文件失败 %s: %w", f.rel, copyErr))
		}
		if n != f.size {
			zw.Close()
			return abort(worldError(fmt.Sprintf("世界文件在备份期间大小变化: %s", f.rel)))
		}
		written += n
		if written > lim.MaxTotalBytes {
			zw.Close()
			return abort(worldError("备份写入总量超过上限"))
		}
	}
	if err := zw.Close(); err != nil {
		return abort(fmt.Errorf("完成 zip 写入失败: %w", err))
	}
	if err := tmp.Chmod(0o600); err != nil {
		return abort(fmt.Errorf("收敛备份权限失败: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return abort(fmt.Errorf("刷新备份到磁盘失败: %w", err))
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return 0, 0, fmt.Errorf("关闭备份临时文件失败: %w", err)
	}
	if err := os.Rename(tmpName, zipPath); err != nil {
		os.Remove(tmpName)
		return 0, 0, fmt.Errorf("备份原子替换失败: %w", err)
	}
	return len(planned), written, nil
}

// umfsFileHex 计算文件的 UMFS 摘要（小写 hex），用于本地备份完整性核对。
func umfsFileHex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := NewUMFSHash()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// worldBackupDirFor 返回某世界的备份目录 root/<world>，并保证名段安全。
func worldBackupDirFor(root, worldName string) (string, error) {
	cleanName, reason := validateWorldName(worldName)
	if reason != nameRejectNone {
		return "", worldError("世界目录名不合法: " + reason)
	}
	dir := filepath.Join(root, cleanName)
	if !PathWithinRoot(dir, root) {
		return "", worldError("备份目录解析越界")
	}
	return dir, nil
}

// uniqueStampZipPath 在备份目录内为时间戳分配一个不存在的 zip 路径，
// 极端的同一秒连续备份用 -01.. 后缀避让，绝不覆盖既有备份。
func uniqueStampZipPath(dir, stamp string) (string, error) {
	if !validateWorldStamp(stamp) {
		return "", worldError("时间戳不合法")
	}
	candidate := filepath.Join(dir, stamp+".zip")
	for i := 0; i < 100; i++ {
		if i == 0 {
			candidate = filepath.Join(dir, stamp+".zip")
		} else {
			candidate = filepath.Join(dir, fmt.Sprintf("%s-%02d.zip", stamp, i))
		}
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", worldError("同一时间戳备份过多，无法分配文件名")
}

// zipPathToManifestPath 返回与某个 zip 配套的清单路径。
func zipPathToManifestPath(zipPath string) string {
	return strings.TrimSuffix(zipPath, ".zip") + ".json"
}

// pruneWorldBackups 按时间戳从新到旧保留 keep 份，淘汰更旧的 zip + 清单。
// 只删除该世界备份目录内、文件名形如 <stamp>.zip 的普通文件，删除数量设上限。
func pruneWorldBackups(dir string, keep int) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	stamps := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".zip") {
			continue
		}
		stamp := strings.TrimSuffix(name, ".zip")
		if validateWorldStamp(stamp) {
			stamps = append(stamps, stamp)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(stamps)))
	if len(stamps) <= keep {
		return 0, nil
	}
	removed := 0
	for _, stamp := range stamps[keep:] {
		if removed >= worldKeepMax {
			break
		}
		zipPath := filepath.Join(dir, stamp+".zip")
		metaPath := filepath.Join(dir, stamp+".json")
		if !PathWithinRoot(zipPath, dir) || !PathWithinRoot(metaPath, dir) {
			continue
		}
		if err := os.Remove(zipPath); err != nil && !os.IsNotExist(err) {
			return removed, err
		}
		_ = os.Remove(metaPath)
		removed++
	}
	return removed, nil
}

// createWorldBackup 是备份主流程：预检 -> 磁盘水位 -> 原子打包 -> UMFS 清单 ->
// 淘汰旧份。纯路径 / 文件操作，不依赖 App 字段，便于以临时目录单测。
func createWorldBackup(worldDir, backupRoot, worldName string, now time.Time, lim WorldBackupLimits) (*WorldBackupMeta, error) {
	lim = normalizeWorldBackupLimits(lim)
	planned, total, err := planWorldFiles(worldDir, lim)
	if err != nil {
		return nil, err
	}
	dir, err := worldBackupDirFor(backupRoot, worldName)
	if err != nil {
		return nil, err
	}
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	// 落盘前做磁盘水位裁决：把源体积 + zip 临时膨胀余量一起申请，会击穿安全
	// 水位就直接拒绝，而不是先写满盘再失败。探测结论 unknown 时保守放行。
	requested := total + worldReserveHeadroom
	if requested < total {
		requested = total // 溢出保护
	}
	fit := probeDownloadDiskFit(dir, requested, 0)
	if fit.Verdict == diskFitShort {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionBlocked,
			"worldbackup", fmt.Sprintf("备份磁盘空间不足，缺口 %d 字节", fit.Shortfall))
		return nil, worldError("磁盘剩余空间不足，已取消备份")
	}

	stamp := now.UTC().Format(worldStampLayout)
	zipPath, err := uniqueStampZipPath(dir, stamp)
	if err != nil {
		return nil, err
	}
	entries, _, err := writeWorldZipAtomic(planned, zipPath, lim)
	if err != nil {
		return nil, err
	}
	digest, err := umfsFileHex(zipPath)
	if err != nil {
		os.Remove(zipPath)
		return nil, fmt.Errorf("计算备份摘要失败: %w", err)
	}
	meta := &WorldBackupMeta{
		WorldName:  worldName,
		Stamp:      stamp,
		CreatedAt:  now.UTC().Format(time.RFC3339),
		Entries:    entries,
		TotalBytes: total,
		ZipName:    filepath.Base(zipPath),
		UMFS:       digest,
	}
	if err := writePrivateJSONBounded(zipPathToManifestPath(zipPath), meta, 1<<20); err != nil {
		os.Remove(zipPath)
		return nil, fmt.Errorf("写入备份清单失败: %w", err)
	}
	_, _ = pruneWorldBackups(dir, lim.Keep)
	return meta, nil
}

// readWorldBackupMeta 读取并核对某备份目录内、指定时间戳的清单与 zip 归属。
func readWorldBackupMeta(dir, worldName, stamp string) (*WorldBackupMeta, string, error) {
	if !validateWorldStamp(stamp) {
		return nil, "", worldError("时间戳不合法")
	}
	zipPath := filepath.Join(dir, stamp+".zip")
	metaPath := zipPathToManifestPath(zipPath)
	if !PathWithinRoot(zipPath, dir) || !PathWithinRoot(metaPath, dir) {
		return nil, "", worldError("备份路径越界")
	}
	if bad, _ := isSymlinkOrSpecial(zipPath); bad {
		recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked,
			"worldbackup", "备份 zip 是符号链接或特殊文件，拒绝: "+stamp)
		return nil, "", worldError("拒绝读取链接形式的备份文件")
	}
	const maxManifestBytes = int64(1) << 20
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, "", worldError("备份清单不存在或不可读")
	}
	if int64(len(raw)) > maxManifestBytes {
		return nil, "", worldError("备份清单超过大小上限")
	}
	var meta WorldBackupMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, "", worldError("解析备份清单失败")
	}
	if meta.WorldName != worldName || meta.ZipName != filepath.Base(zipPath) {
		recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked,
			"worldbackup", "备份清单与文件名/世界归属不一致: "+stamp)
		return nil, "", worldError("备份清单归属校验失败")
	}
	return &meta, zipPath, nil
}

// listWorldBackups 列出某世界现存备份（按时间戳从新到旧）。缺失 / 损坏清单不致命，
// 用 zip 文件本身兜底列出条目，避免一个坏清单导致整个恢复入口不可用。
func listWorldBackups(backupRoot, worldName string) ([]WorldBackupMeta, error) {
	dir, err := worldBackupDirFor(backupRoot, worldName)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []WorldBackupMeta{}, nil
		}
		return nil, err
	}
	out := make([]WorldBackupMeta, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".zip") {
			continue
		}
		stamp := strings.TrimSuffix(e.Name(), ".zip")
		if !validateWorldStamp(stamp) {
			continue
		}
		if bad, _ := isSymlinkOrSpecial(filepath.Join(dir, e.Name())); bad {
			continue
		}
		if meta, _, mErr := readWorldBackupMeta(dir, worldName, stamp); mErr == nil {
			out = append(out, *meta)
		} else {
			info, _ := e.Info()
			fallback := WorldBackupMeta{WorldName: worldName, Stamp: stamp, ZipName: e.Name()}
			if info != nil {
				fallback.CreatedAt = info.ModTime().UTC().Format(time.RFC3339)
			}
			out = append(out, fallback)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Stamp > out[j].Stamp })
	return out, nil
}

// restoreWorldBackup 把指定备份恢复成一个“全新、不覆盖”的世界目录。
//
// 恢复前强制重算 zip 的 UMFS 并与清单核对，防止备份被掉包 / 损坏后解出脏数据；
// 解压完全复用 zipextract 的 Zip Slip / 特殊条目 / 炸弹规划，空前缀表示 zip 内
// 路径就是相对世界根的完整相对路径。目标目录已存在时绝不覆盖，改为分配唯一名。
func restoreWorldBackup(savesDir, backupRoot, worldName, stamp string, lim WorldBackupLimits) (string, error) {
	lim = normalizeWorldBackupLimits(lim)
	if _, reason := validateWorldName(worldName); reason != nameRejectNone {
		return "", worldError("世界目录名不合法: " + reason)
	}
	dir, err := worldBackupDirFor(backupRoot, worldName)
	if err != nil {
		return "", err
	}
	meta, zipPath, err := readWorldBackupMeta(dir, worldName, stamp)
	if err != nil {
		return "", err
	}
	digest, err := umfsFileHex(zipPath)
	if err != nil {
		return "", fmt.Errorf("重算备份摘要失败: %w", err)
	}
	if meta.UMFS == "" || digest != meta.UMFS {
		recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked,
			"worldbackup", "备份 UMFS 摘要不一致，疑似损坏或被篡改: "+stamp)
		return "", worldError("备份完整性校验失败，已拒绝恢复")
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("打开备份 zip 失败: %w", err)
	}
	defer zr.Close()

	target, err := allocateRestoreDir(savesDir, worldName, stamp)
	if err != nil {
		return "", err
	}
	if err := ensurePrivateDir(target); err != nil {
		return "", err
	}
	zipLim := zipExtractLimits{
		EntryMax:   lim.MaxEntryBytes,
		TotalMax:   lim.MaxTotalBytes,
		MaxEntries: lim.MaxEntries,
	}
	// 空前缀：zip 内 "level.dat"、"region/r.0.0.mca" 等路径原样作为相对目标根路径。
	if _, _, err := extractZipPrefixes(zr.File, target, []string{""}, zipLim, nil); err != nil {
		os.RemoveAll(target)
		recordSecurityEvent(auditCategoryZip, auditSeverityCritical, auditActionBlocked,
			"worldbackup", "备份恢复解压失败，已清理半成品: "+err.Error())
		return "", worldError("备份解压失败，已取消恢复")
	}
	if empty, _ := isWorldDirEmpty(target); empty {
		os.RemoveAll(target)
		return "", worldError("备份内容为空，已取消恢复")
	}
	return target, nil
}

// isWorldDirEmpty 报告目录是否不含任何条目。解压后用它兜底发现“空备份”。
func isWorldDirEmpty(dir string) (bool, error) {
	f, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer f.Close()
	names, err := f.Readdirnames(1)
	if err != nil && err != io.EOF {
		return false, err
	}
	return len(names) == 0, nil
}

// allocateRestoreDir 在 saves 下为恢复结果分配一个不存在的目录：
// saves/<world>-restored-<stamp>，冲突时追加 -01..。绝不覆盖既有世界。
func allocateRestoreDir(savesDir, worldName, stamp string) (string, error) {
	cleanName, reason := validateWorldName(worldName)
	if reason != nameRejectNone {
		return "", worldError("世界目录名不合法: " + reason)
	}
	if !validateWorldStamp(stamp) {
		return "", worldError("时间戳不合法")
	}
	base := cleanName + "-restored-" + stamp
	if len(base) > 200 {
		return "", worldError("恢复目录名过长")
	}
	for i := 0; i < 100; i++ {
		name := base
		if i > 0 {
			name = fmt.Sprintf("%s-%02d", base, i)
		}
		target := filepath.Join(savesDir, name)
		if !PathWithinRoot(target, savesDir) {
			return "", worldError("恢复目录解析越界")
		}
		if _, err := os.Lstat(target); err != nil {
			if os.IsNotExist(err) {
				return target, nil
			}
			return "", err
		}
	}
	return "", worldError("无法为恢复结果分配唯一目录")
}
