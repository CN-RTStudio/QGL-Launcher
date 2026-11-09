package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRegionFile(t *testing.T, path string, slots map[int][2]int, sectors int) {
	t.Helper()
	size := regionHeaderBytes + sectors*regionSectorBytes
	data := make([]byte, size)
	for index, value := range slots {
		base := index * 4
		data[base] = byte(value[0] >> 16)
		data[base+1] = byte(value[0] >> 8)
		data[base+2] = byte(value[0])
		data[base+3] = byte(value[1])
		offset := value[0] * regionSectorBytes
		if offset+3 < len(data) {
			data[offset+3] = 4
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("写入区域文件失败: %v", err)
	}
}

func TestAuditWorldRegionsClean(t *testing.T) {
	world := t.TempDir()
	regionDir := filepath.Join(world, "region")
	if err := os.Mkdir(regionDir, 0o700); err != nil {
		t.Fatalf("创建 region 失败: %v", err)
	}
	writeRegionFile(t, filepath.Join(regionDir, "r.0.0.mca"), map[int][2]int{0: {2, 1}}, 4)
	audit, err := AuditWorldRegions(world)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Blocking() || len(audit.Findings) != 0 {
		t.Fatalf("正常区域文件不应有问题: %s", audit.Describe())
	}
	if audit.Chunks != 1 {
		t.Fatalf("应统计到 1 个分块")
	}
}

func TestAuditWorldRegionsOutOfRange(t *testing.T) {
	world := t.TempDir()
	regionDir := filepath.Join(world, "region")
	os.Mkdir(regionDir, 0o700)
	writeRegionFile(t, filepath.Join(regionDir, "r.0.0.mca"), map[int][2]int{1: {999, 1}}, 4)
	audit, err := AuditWorldRegions(world)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() || !strings.Contains(strings.Join(audit.Codes(), ","), regionReasonOutOfRange) {
		t.Fatalf("越界扇区应阻断: %s", audit.Describe())
	}
}

func TestAuditWorldRegionsBadOffset(t *testing.T) {
	world := t.TempDir()
	regionDir := filepath.Join(world, "region")
	os.Mkdir(regionDir, 0o700)
	writeRegionFile(t, filepath.Join(regionDir, "r.0.0.mca"), map[int][2]int{2: {1, 1}}, 4)
	audit, err := AuditWorldRegions(world)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !strings.Contains(strings.Join(audit.Codes(), ","), regionReasonBadOffset) {
		t.Fatalf("非法偏移应报告: %v", audit.Codes())
	}
}

func TestAuditWorldRegionsShortHeader(t *testing.T) {
	world := t.TempDir()
	regionDir := filepath.Join(world, "region")
	os.Mkdir(regionDir, 0o700)
	if err := os.WriteFile(filepath.Join(regionDir, "r.0.0.mca"), []byte("short"), 0o600); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	audit, err := AuditWorldRegions(world)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("头部长不足应阻断: %s", audit.Describe())
	}
}

func TestAuditWorldRegionsSymlink(t *testing.T) {
	world := t.TempDir()
	regionDir := filepath.Join(world, "region")
	os.Mkdir(regionDir, 0o700)
	outside := filepath.Join(t.TempDir(), "r.0.0.mca")
	writeRegionFile(t, outside, map[int][2]int{}, 2)
	if err := os.Symlink(outside, filepath.Join(regionDir, "r.0.0.mca")); err != nil {
		t.Skipf("创建符号链接失败: %v", err)
	}
	audit, err := AuditWorldRegions(world)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("符号链接区域文件应阻断: %s", audit.Describe())
	}
}

func TestAuditWorldRegionsBadName(t *testing.T) {
	world := t.TempDir()
	regionDir := filepath.Join(world, "region")
	os.Mkdir(regionDir, 0o700)
	if err := os.WriteFile(filepath.Join(regionDir, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	audit, err := AuditWorldRegions(world)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Blocking() != false || len(audit.Findings) == 0 {
		t.Fatalf("异常文件名应告警不阻断: %s", audit.Describe())
	}
}

func TestAuditWorldRegionsMissingDir(t *testing.T) {
	audit, err := AuditWorldRegions(t.TempDir())
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.RegionDirs != 0 || audit.Blocking() || len(audit.Findings) != 0 {
		t.Fatalf("缺失区域目录应按空处理")
	}
}
