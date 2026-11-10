package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

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

func (a *App) worldBackupRoot() string {
	return filepath.Join(a.GetQGLDir(), worldBackupRootFolder)
}
func (a *App) resolveSavesDir(gameDirHint string) (string, error) {
	mcDir := a.GetMinecraftDir()
	if mcDir == "" {
		return "", worldError("无法解析 .minecraft 根目录")
	}
	gameDir := mcDir
	if hint := strings.TrimSpace(gameDirHint); hint != "" {
		candidate := filepath.Clean(hint)
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(mcDir, candidate)
		}
		if !PathWithinRoot(candidate, mcDir) {
			recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
				"worldbackup", "世界备份 gameDir 越出 .minecraft 根: "+hint)
			return "", worldError("游戏目录必须位于 .minecraft 之内")
		}
		gameDir = candidate
	}
	savesDir := filepath.Join(gameDir, worldSavesFolder)
	if !PathWithinRoot(savesDir, mcDir) {
		return "", worldError("saves 目录解析越界")
	}
	return savesDir, nil
}

func (a *App) ListWorlds(gameDirHint string) ([]WorldInfo, error) {
	savesDir, err := a.resolveSavesDir(gameDirHint)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(savesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []WorldInfo{}, nil
		}
		return nil, worldError("读取 saves 目录失败")
	}
	lim := defaultWorldBackupLimits()
	worlds := make([]WorldInfo, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if _, reason := validateWorldName(name); reason != nameRejectNone {
			continue
		}
		worldDir := filepath.Join(savesDir, name)
		// e.IsDir() 对符号链接（含指向目录的链接）返回 false，已在上面跳过，
		// 故到达此处的必然是真实目录；不要再用把普通目录当特殊项的判定，否则
		// 会把所有合法世界都过滤掉。
		planned, total, planErr := planWorldFiles(worldDir, lim)
		if planErr != nil {
			// 体量超限 / 含特殊链接的世界不可直接备份，但仍在列表里给出名字，
			// 体量留 0，让前端能看到并提示，而不是整列失败。
			worlds = append(worlds, WorldInfo{Name: name})
			continue
		}
		info := WorldInfo{Name: name, Entries: len(planned), TotalBytes: total}
		if fi, fErr := e.Info(); fErr == nil {
			info.ModTime = fi.ModTime().UTC().Format(time.RFC3339)
		}
		worlds = append(worlds, info)
	}
	sort.Slice(worlds, func(i, j int) bool { return worlds[i].Name < worlds[j].Name })
	return worlds, nil
}

func (a *App) BackupWorld(gameDirHint, worldName string) (*WorldBackupMeta, error) {
	savesDir, err := a.resolveSavesDir(gameDirHint)
	if err != nil {
		return nil, err
	}
	worldDir, err := resolveWorldDir(savesDir, worldName)
	if err != nil {
		return nil, err
	}
	return createWorldBackup(worldDir, a.worldBackupRoot(), strings.TrimSpace(worldName),
		time.Now(), defaultWorldBackupLimits())
}
func (a *App) ListWorldBackups(worldName string) ([]WorldBackupMeta, error) {
	return listWorldBackups(a.worldBackupRoot(), strings.TrimSpace(worldName))
}
func (a *App) RestoreWorldBackup(gameDirHint, worldName, stamp string) (string, error) {
	savesDir, err := a.resolveSavesDir(gameDirHint)
	if err != nil {
		return "", err
	}
	return restoreWorldBackup(savesDir, a.worldBackupRoot(),
		strings.TrimSpace(worldName), strings.TrimSpace(stamp), defaultWorldBackupLimits())
}

func (a *App) DeleteWorldBackup(worldName, stamp string) error {
	cleanName, reason := validateWorldName(strings.TrimSpace(worldName))
	if reason != nameRejectNone {
		return worldError("世界目录名不合法: " + reason)
	}
	if !validateWorldStamp(strings.TrimSpace(stamp)) {
		return worldError("时间戳不合法")
	}
	dir, err := worldBackupDirFor(a.worldBackupRoot(), cleanName)
	if err != nil {
		return err
	}
	zipPath := filepath.Join(dir, stamp+".zip")
	metaPath := zipPathToManifestPath(zipPath)
	if !PathWithinRoot(zipPath, dir) || !PathWithinRoot(metaPath, dir) {
		return worldError("备份路径越界")
	}
	if err := os.Remove(zipPath); err != nil && !os.IsNotExist(err) {
		return worldError("删除备份失败")
	}
	if err := os.Remove(metaPath); err != nil && !os.IsNotExist(err) {
		return worldError("删除备份清单失败")
	}
	return nil
}

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
	raw, err := readBoundedFile(metaPath, auditTextReadMaxBytes)
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
