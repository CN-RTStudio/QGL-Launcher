package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func AuditServerLevelData(serverDir string) *LevelDataAudit {
	a := &LevelDataAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("world/level.dat", sldReasonMiss, "未配置服务器目录", false)
		return a
	}
	const rel = "world/level.dat"
	path := filepath.Join(serverDir, filepath.FromSlash(rel))
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(rel, sldReasonRead, err.Error(), true)
		return a
	}
	if link {
		a.add(rel, sldReasonLink, "存档元数据是符号链接或特殊文件", true)
		return a
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(rel, sldReasonMiss, "未找到 level.dat", false)
		return a
	}
	info, err := os.Stat(path)
	if err != nil {
		a.add(rel, sldReasonRead, err.Error(), true)
		return a
	}
	if info.Size() > sldMaxFile {
		a.add(rel, sldReasonLarge, fmt.Sprintf("文件 %d 字节", info.Size()), true)
		return a
	}
	data, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		a.add(rel, sldReasonRead, err.Error(), true)
		return a
	}
	if len(data) < 8 || !bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		a.add(rel, sldReasonMagic, "缺少 gzip 头", true)
		return a
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		a.add(rel, sldReasonNBT, "gzip 解压失败", true)
		return a
	}
	inner, err := io.ReadAll(io.LimitReader(zr, sldMaxFile+1))
	zr.Close()
	if err != nil {
		a.add(rel, sldReasonNBT, "gzip 流损坏", true)
		return a
	}
	if int64(len(inner)) > sldMaxFile {
		a.add(rel, sldReasonLarge, "解压后超过上限", true)
		return a
	}
	data = inner
	if !bytes.Contains(data, []byte("Data")) {
		a.add(rel, sldReasonNBT, "NBT 结构中缺少 Data 根", true)
	}
	if !bytes.Contains(data, []byte("LevelName")) {
		a.add(rel, sldReasonNBT, "缺少 LevelName 字段", false)
	}
	name := sldPrintableString(data, "LevelName")
	if name != "" && cfgHasControlChars(name) {
		a.add(rel, sldReasonName, "世界名含控制字符", true)
	}
	if bytes.Contains(data, []byte("allowCommands")) && bytes.Contains(data, []byte{0x00, 0x01, 0x01}) {
		a.add(rel, sldReasonAllow, "存档默认开启命令", false)
	}
	if bytes.Contains(data, []byte("hardcore")) && bytes.Contains(data, []byte{0x00, 0x01, 0x01}) {
		a.add(rel, sldReasonHard, "硬核模式存档", false)
	}
	if bytes.Contains(data, []byte("generatorName")) && !bytes.Contains(data, []byte("default")) && !bytes.Contains(data, []byte("flat")) && !bytes.Contains(data, []byte("largeBiomes")) {
		a.add(rel, sldReasonGen, "自定义地形生成器", false)
	}
	if bytes.Contains(data, []byte("worldGenSettings")) && !bytes.Contains(data, []byte("seed")) {
		a.add(rel, sldReasonSeed, "世界生成设置缺少种子字段", false)
	}
	return a
}
