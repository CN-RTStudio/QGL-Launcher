package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type instanceRecord struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Loader   string `json:"loader"`
	Isolated bool   `json:"isolated"`
}

const instanceMetaFile = "instance.json"

var errInstanceName = errors.New("非法实例名")

func validateInstanceName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || len(trimmed) > 64 {
		return errInstanceName
	}
	if trimmed == "." || trimmed == ".." {
		return errInstanceName
	}
	if strings.ContainsAny(trimmed, "/\\:*?\"<>|") {
		return errInstanceName
	}
	for _, r := range trimmed {
		if r < 0x20 || r == 0x7f {
			return errInstanceName
		}
	}
	return nil
}

func resolveInstanceDir(root string, name string) (string, error) {
	if err := validateInstanceName(name); err != nil {
		return "", err
	}
	base, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "instances", name)
	rel, err := filepath.Rel(base, dir)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errInstanceName
	}
	return dir, nil
}

func readInstanceMeta(dir string) (instanceRecord, error) {
	var rec instanceRecord
	path := filepath.Join(dir, instanceMetaFile)
	info, err := os.Lstat(path)
	if err != nil {
		return rec, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64<<10 {
		return rec, errors.New("实例元数据不可用")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return rec, err
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		return rec, err
	}
	if err := validateInstanceName(rec.Name); err != nil {
		return rec, err
	}
	return rec, nil
}

func listInstances(root string) ([]instanceRecord, error) {
	base, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(base, "instances")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]instanceRecord, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		rec, err := readInstanceMeta(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		if rec.Name != entry.Name() {
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func saveInstanceMeta(root string, rec instanceRecord) error {
	dir, err := resolveInstanceDir(root, rec.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".instance-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filepath.Join(dir, instanceMetaFile))
}

func instanceGameDir(root string, rec instanceRecord) (string, error) {
	base, err := resolveInstanceDir(root, rec.Name)
	if err != nil {
		return "", err
	}
	if rec.Isolated {
		return filepath.Join(base, "game"), nil
	}
	shared, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return shared, nil
}

func instanceSummary(recs []instanceRecord) string {
	if len(recs) == 0 {
		return "尚无实例"
	}
	var b strings.Builder
	b.WriteString("共 ")
	b.WriteString(strconv.Itoa(len(recs)))
	b.WriteString(" 个实例: ")
	for i, rec := range recs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(rec.Name)
		if rec.Version != "" {
			b.WriteString("(" + rec.Version + ")")
		}
	}
	return b.String()
}
