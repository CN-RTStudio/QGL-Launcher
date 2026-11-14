package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	packImportMaxEntries = 20000
	packImportMaxBytes   = int64(512 * 1024 * 1024)
	packImportMaxEntry   = int64(64 * 1024 * 1024)
	packManifestName     = "manifest.json"
	packModsDir          = "mods"
)

var (
	errPackArchiveInvalid = errors.New("整合包压缩文件不可用")
	errPackEntryUnsafe    = errors.New("整合包内存在越界路径")
	errPackTooLarge       = errors.New("整合包体积超过上限")
	errPackNoManifest     = errors.New("整合包缺少 manifest.json")
	errPackTargetExists   = errors.New("目标实例目录已存在")
)

type packEntry struct {
	Name  string
	IsDir bool
	Size  int64
}

type packArchive struct {
	Entries   []packEntry
	ModCount  int
	TotalSize int64
	Manifest  string
}

func packSafeEntryName(name string) (string, error) {
	if name == "" {
		return "", errPackEntryUnsafe
	}
	cleaned := strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(cleaned, "/") {
		return "", errPackEntryUnsafe
	}
	if strings.Contains(cleaned, "\x00") {
		return "", errPackEntryUnsafe
	}
	normalized := path.Clean(cleaned)
	if normalized == "." {
		return "", errPackEntryUnsafe
	}
	if normalized == ".." || strings.HasPrefix(normalized, "../") {
		return "", errPackEntryUnsafe
	}
	if strings.Contains(normalized, ":") {
		return "", errPackEntryUnsafe
	}
	return normalized, nil
}

func packInspectArchive(archivePath string) (*packArchive, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, errPackArchiveInvalid
	}
	defer reader.Close()
	if len(reader.File) > packImportMaxEntries {
		return nil, errPackTooLarge
	}
	archive := &packArchive{}
	for _, entry := range reader.File {
		name, nameErr := packSafeEntryName(entry.Name)
		if nameErr != nil {
			return nil, errPackEntryUnsafe
		}
		if entry.UncompressedSize64 > uint64(packImportMaxEntry) {
			return nil, errPackTooLarge
		}
		isDir := strings.HasSuffix(entry.Name, "/") || entry.FileInfo().IsDir()
		archive.Entries = append(archive.Entries, packEntry{
			Name:  name,
			IsDir: isDir,
			Size:  int64(entry.UncompressedSize64),
		})
		if isDir {
			continue
		}
		archive.TotalSize += int64(entry.UncompressedSize64)
		if archive.TotalSize > packImportMaxBytes {
			return nil, errPackTooLarge
		}
		if path.Dir(name) == packModsDir && strings.HasSuffix(strings.ToLower(name), ".jar") {
			archive.ModCount++
		}
		if !strings.Contains(name, "/") && strings.EqualFold(name, packManifestName) {
			archive.Manifest = name
		}
	}
	if archive.Manifest == "" {
		return nil, errPackNoManifest
	}
	if len(archive.Entries) == 0 {
		return nil, errPackArchiveInvalid
	}
	return archive, nil
}

func packResolveTarget(instancesRoot, instanceName string) (string, error) {
	if err := validateInstanceName(instanceName); err != nil {
		return "", err
	}
	root := filepath.Clean(instancesRoot)
	target := filepath.Join(root, instanceName)
	if _, boundErr := pathInsideRoot(root, target); boundErr != nil {
		return "", errPackEntryUnsafe
	}
	if _, statErr := os.Stat(target); statErr == nil {
		return "", errPackTargetExists
	}
	return target, nil
}

func packExtract(archivePath, targetDir string) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return errPackArchiveInvalid
	}
	defer reader.Close()
	root := filepath.Clean(targetDir)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	for _, entry := range reader.File {
		name, nameErr := packSafeEntryName(entry.Name)
		if nameErr != nil {
			return errPackEntryUnsafe
		}
		dest := filepath.Join(root, filepath.FromSlash(name))
		if _, boundErr := pathInsideRoot(root, dest); boundErr != nil {
			return errPackEntryUnsafe
		}
		if strings.HasSuffix(entry.Name, "/") || entry.FileInfo().IsDir() {
			if mkErr := os.MkdirAll(dest, 0o755); mkErr != nil {
				return mkErr
			}
			continue
		}
		if mkErr := os.MkdirAll(filepath.Dir(dest), 0o755); mkErr != nil {
			return mkErr
		}
		src, openErr := entry.Open()
		if openErr != nil {
			return openErr
		}
		dst, createErr := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if createErr != nil {
			src.Close()
			return createErr
		}
		written, copyErr := io.Copy(dst, io.LimitReader(src, packImportMaxEntry))
		dst.Close()
		src.Close()
		if copyErr != nil {
			return copyErr
		}
		if written > packImportMaxEntry {
			return errPackTooLarge
		}
	}
	return nil
}

func packImportSummary(archive *packArchive, instanceName string, target string) string {
	if archive == nil {
		return "整合包信息缺失"
	}
	return fmt.Sprintf("%s → %s（%d 个文件，%d 个模组，%.1f MB）",
		archive.Manifest, instanceName, len(archive.Entries), archive.ModCount,
		float64(archive.TotalSize)/1048576.0)
}

func packImportInstance(instancesRoot, archivePath, instanceName string) (string, error) {
	archive, inspectErr := packInspectArchive(archivePath)
	if inspectErr != nil {
		return "", inspectErr
	}
	target, targetErr := packResolveTarget(instancesRoot, instanceName)
	if targetErr != nil {
		return "", targetErr
	}
	if extractErr := packExtract(archivePath, target); extractErr != nil {
		return "", extractErr
	}
	return packImportSummary(archive, instanceName, target), nil
}
