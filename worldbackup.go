package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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

func validateWorldName(name string) (string, string) {
	trimmed := strings.TrimSpace(name)
	if reason := auditComponent(trimmed, maxWorldNameLen); reason != nameRejectNone {
		return "", reason
	}
	return trimmed, nameRejectNone
}
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
	return umfsFile(path)
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
