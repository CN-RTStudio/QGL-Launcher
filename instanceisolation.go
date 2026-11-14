package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var errIsolationPath = errors.New("隔离路径越界")

const isolationOptInFile = ".isolate"

func pathInsideRoot(root string, target string) (string, error) {
	base, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(base, abs)
	if err != nil {
		return "", err
	}
	if rel == "." {
		return base, nil
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errIsolationPath
	}
	return abs, nil
}

func hasIsolationMarker(dir string) bool {
	info, err := os.Lstat(filepath.Join(dir, isolationOptInFile))
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

func resolveGameDir(root string, name string, isolated bool) (string, error) {
	instanceDir, err := resolveInstanceDir(root, name)
	if err != nil {
		return "", err
	}
	if !isolated && !hasIsolationMarker(instanceDir) {
		return pathInsideRoot(root, root)
	}
	target := filepath.Join(instanceDir, "game")
	if _, statErr := os.Lstat(target); statErr != nil {
		if !os.IsNotExist(statErr) {
			return "", statErr
		}
		if err := os.MkdirAll(target, 0o755); err != nil {
			return "", err
		}
	} else {
		info, infoErr := os.Lstat(target)
		if infoErr != nil {
			return "", infoErr
		}
		if !info.IsDir() {
			return "", errIsolationPath
		}
	}
	return pathInsideRoot(root, target)
}

func isolationDirectories(root string, name string) ([]string, error) {
	gameDir, err := resolveGameDir(root, name, true)
	if err != nil {
		return nil, err
	}
	subs := []string{"mods", "config", "resourcepacks", "shaderpacks", "saves", "logs"}
	out := make([]string, 0, len(subs))
	for _, sub := range subs {
		dir := filepath.Join(gameDir, sub)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		if _, err := pathInsideRoot(root, dir); err != nil {
			return nil, err
		}
		out = append(out, dir)
	}
	return out, nil
}

func isolationStatus(root string, name string) (bool, string, error) {
	instanceDir, err := resolveInstanceDir(root, name)
	if err != nil {
		return false, "", err
	}
	if hasIsolationMarker(instanceDir) {
		return true, filepath.Join(instanceDir, "game"), nil
	}
	rec, err := readInstanceMeta(instanceDir)
	if err == nil && rec.Isolated {
		return true, filepath.Join(instanceDir, "game"), nil
	}
	return false, root, nil
}

func toggleIsolation(root string, name string, enabled bool) error {
	instanceDir, err := resolveInstanceDir(root, name)
	if err != nil {
		return err
	}
	marker := filepath.Join(instanceDir, isolationOptInFile)
	if enabled {
		if err := os.MkdirAll(instanceDir, 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(marker, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		return f.Close()
	}
	if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
