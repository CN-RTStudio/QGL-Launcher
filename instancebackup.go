package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	instanceBackupDir      = "backups"
	instanceBackupMetaFile = "backup.json"
	instanceBackupMaxFiles = 50000
	instanceBackupMaxDepth = 24
)

var (
	errBackupNameInvalid = errors.New("备份名称不可用")
	errBackupSourceGone  = errors.New("实例目录不存在")
	errBackupCorrupted   = errors.New("备份元数据损坏")
	errBackupRestoreBusy = errors.New("目标目录非空，拒绝覆盖恢复")
)

type backupEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Digest string `json:"sha256"`
}

type backupManifest struct {
	Instance  string        `json:"instance"`
	CreatedAt string        `json:"created_at"`
	Entries   []backupEntry `json:"entries"`
	TotalSize int64         `json:"total_size"`
}

func backupValidateName(name string) error {
	if name == "" || len(name) > 64 {
		return errBackupNameInvalid
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		if r == '-' || r == '_' {
			continue
		}
		return errBackupNameInvalid
	}
	return nil
}

func backupHashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hasher := sha256.New()
	written, copyErr := io.Copy(hasher, file)
	if copyErr != nil {
		return "", 0, copyErr
	}
	return hex.EncodeToString(hasher.Sum(nil)), written, nil
}

func backupWalkFiles(root string) ([]backupEntry, int64, error) {
	entries := make([]backupEntry, 0, 128)
	var total int64
	rootClean := filepath.Clean(root)
	walkErr := filepath.Walk(rootClean, func(current string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(rootClean, current)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		if strings.Count(rel, string(os.PathSeparator)) > instanceBackupMaxDepth {
			return errBackupCorrupted
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if len(entries) >= instanceBackupMaxFiles {
			return errBackupCorrupted
		}
		digest, size, hashErr := backupHashFile(current)
		if hashErr != nil {
			return hashErr
		}
		entries = append(entries, backupEntry{Path: rel, Size: size, Digest: digest})
		total += size
		return nil
	})
	if walkErr != nil {
		return nil, 0, walkErr
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, total, nil
}

func backupCreate(instancesRoot, instanceName, backupName string) (string, error) {
	if err := validateInstanceName(instanceName); err != nil {
		return "", err
	}
	if err := backupValidateName(backupName); err != nil {
		return "", err
	}
	source, sourceErr := resolveInstanceDir(instancesRoot, instanceName)
	if sourceErr != nil {
		return "", sourceErr
	}
	if info, statErr := os.Stat(source); statErr != nil || !info.IsDir() {
		return "", errBackupSourceGone
	}
	backupRoot := filepath.Join(instancesRoot, instanceName, instanceBackupDir)
	if _, boundErr := pathInsideRoot(filepath.Join(instancesRoot, instanceName), backupRoot); boundErr != nil {
		return "", errIsolationPath
	}
	target := filepath.Join(backupRoot, backupName)
	if _, existsErr := os.Stat(target); existsErr == nil {
		return "", errBackupNameInvalid
	}
	if mkErr := os.MkdirAll(target, 0o755); mkErr != nil {
		return "", mkErr
	}
	entries, total, walkErr := backupWalkFiles(source)
	if walkErr != nil {
		return "", walkErr
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Path, instanceBackupDir+string(os.PathSeparator)) {
			continue
		}
		srcPath := filepath.Join(source, entry.Path)
		dstPath := filepath.Join(target, entry.Path)
		if _, boundErr := pathInsideRoot(target, dstPath); boundErr != nil {
			return "", errIsolationPath
		}
		if mkErr := os.MkdirAll(filepath.Dir(dstPath), 0o755); mkErr != nil {
			return "", mkErr
		}
		if copyErr := backupCopyFile(srcPath, dstPath); copyErr != nil {
			return "", copyErr
		}
	}
	manifest := backupManifest{
		Instance:  instanceName,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Entries:   entries,
		TotalSize: total,
	}
	payload, marshalErr := json.MarshalIndent(manifest, "", "  ")
	if marshalErr != nil {
		return "", marshalErr
	}
	metaPath := filepath.Join(target, instanceBackupMetaFile)
	tempPath := metaPath + ".tmp"
	if writeErr := os.WriteFile(tempPath, payload, 0o644); writeErr != nil {
		return "", writeErr
	}
	if renameErr := os.Rename(tempPath, metaPath); renameErr != nil {
		return "", renameErr
	}
	return fmt.Sprintf("备份 %s 完成：%d 个文件，%.1f MB", backupName, len(entries), float64(total)/1048576.0), nil
}

func backupCopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, statErr := in.Stat()
	if statErr != nil {
		return statErr
	}
	if !info.Mode().IsRegular() {
		return errBackupCorrupted
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	written, copyErr := io.Copy(out, in)
	if copyErr != nil {
		return copyErr
	}
	if written != info.Size() {
		return errBackupCorrupted
	}
	return nil
}

func backupReadManifest(instancesRoot, instanceName, backupName string) (*backupManifest, string, error) {
	if err := backupValidateName(backupName); err != nil {
		return nil, "", err
	}
	metaPath := filepath.Join(instancesRoot, instanceName, instanceBackupDir, backupName, instanceBackupMetaFile)
	raw, readErr := os.ReadFile(metaPath)
	if readErr != nil {
		return nil, "", errBackupCorrupted
	}
	var manifest backupManifest
	if unmarshalErr := json.Unmarshal(raw, &manifest); unmarshalErr != nil {
		return nil, "", errBackupCorrupted
	}
	if manifest.Instance != instanceName {
		return nil, "", errBackupCorrupted
	}
	return &manifest, filepath.Dir(metaPath), nil
}

func backupVerify(instancesRoot, instanceName, backupName string) (string, error) {
	manifest, dir, err := backupReadManifest(instancesRoot, instanceName, backupName)
	if err != nil {
		return "", err
	}
	mismatched := 0
	missing := 0
	for _, entry := range manifest.Entries {
		filePath := filepath.Join(dir, entry.Path)
		if _, boundErr := pathInsideRoot(dir, filePath); boundErr != nil {
			return "", errIsolationPath
		}
		info, statErr := os.Lstat(filePath)
		if statErr != nil {
			missing++
			continue
		}
		if !info.Mode().IsRegular() {
			mismatched++
			continue
		}
		if info.Size() != entry.Size {
			mismatched++
			continue
		}
		digest, _, hashErr := backupHashFile(filePath)
		if hashErr != nil {
			return "", hashErr
		}
		if digest != entry.Digest {
			mismatched++
		}
	}
	if missing > 0 || mismatched > 0 {
		return "", fmt.Errorf("%w：缺失 %d，校验不符 %d", errBackupCorrupted, missing, mismatched)
	}
	return fmt.Sprintf("备份 %s 校验通过：%d 个文件", backupName, len(manifest.Entries)), nil
}

func backupRestore(instancesRoot, instanceName, backupName, targetName string) (string, error) {
	manifest, dir, err := backupReadManifest(instancesRoot, instanceName, backupName)
	if err != nil {
		return "", err
	}
	target, targetErr := packResolveTarget(instancesRoot, targetName)
	if targetErr != nil {
		return "", targetErr
	}
	if mkErr := os.MkdirAll(target, 0o755); mkErr != nil {
		return "", mkErr
	}
	restored := 0
	for _, entry := range manifest.Entries {
		srcPath := filepath.Join(dir, entry.Path)
		if _, boundErr := pathInsideRoot(dir, srcPath); boundErr != nil {
			os.RemoveAll(target)
			return "", errIsolationPath
		}
		srcInfo, linkErr := os.Lstat(srcPath)
		if linkErr != nil {
			os.RemoveAll(target)
			return "", linkErr
		}
		if !srcInfo.Mode().IsRegular() {
			os.RemoveAll(target)
			return "", errBackupCorrupted
		}
		dstPath := filepath.Join(target, entry.Path)
		if _, boundErr := pathInsideRoot(target, dstPath); boundErr != nil {
			os.RemoveAll(target)
			return "", errIsolationPath
		}
		if mkErr := os.MkdirAll(filepath.Dir(dstPath), 0o755); mkErr != nil {
			os.RemoveAll(target)
			return "", mkErr
		}
		if copyErr := backupCopyFile(srcPath, dstPath); copyErr != nil {
			os.RemoveAll(target)
			return "", copyErr
		}
		restored++
	}
	return fmt.Sprintf("已从 %s 恢复到 %s：%d 个文件", backupName, targetName, restored), nil
}

func backupList(instancesRoot, instanceName string) []string {
	dir := filepath.Join(instancesRoot, instanceName, instanceBackupDir)
	items, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		if !item.IsDir() {
			continue
		}
		metaPath := filepath.Join(dir, item.Name(), instanceBackupMetaFile)
		if _, statErr := os.Stat(metaPath); statErr != nil {
			continue
		}
		names = append(names, item.Name())
	}
	sort.Strings(names)
	return names
}
