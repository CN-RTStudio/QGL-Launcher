package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func AuditServerPropertiesBudget(serverDir string) *PropertiesBudgetAudit {
	a := &PropertiesBudgetAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", sprReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", sprReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", sprReasonMissing, "服务器目录不存在", false)
		return a
	}
	path := filepath.Join(serverDir, "server.properties")
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add("server.properties", sprReasonSymlink, "配置文件为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, sprMaxProps)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			a.add(".", sprReasonMissing, "未发现 server.properties", false)
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add("server.properties", sprReasonTooLarge, fmt.Sprintf("配置文件超过 %d 字节", sprMaxProps), true)
			return a
		}
		a.add("server.properties", sprReasonUnreadable, "配置文件不可读", false)
		return a
	}
	props := sprParseProperties(string(data))
	a.Keys = len(props.Values)
	if a.Keys == 0 && strings.TrimSpace(string(data)) != "" {
		a.add("server.properties", sprReasonBadConfig, "未解析出任何键值", false)
		return a
	}
	if props.LongLines > 0 {
		a.add("server.properties", sprReasonBadConfig, fmt.Sprintf("存在 %d 行超长键值", props.LongLines), false)
	}
	sprCheckViewDistance(a, props)
	sprCheckCompression(a, props)
	sprCheckWatchdog(a, props)
	sprCheckPorts(a, props)
	sprCheckLevelName(a, props)
	sprCheckResourcePack(a, props)
	sprCheckDuplicates(a, props)
	if a.Keys == 0 {
		a.add(".", sprReasonMissing, "server.properties 为空", false)
	}
	return a
}

func sprCheckInt(a *PropertiesBudgetAudit, props sprProperties, key string) (int, bool) {
	value, ok := props.Values[key]
	if !ok {
		return 0, false
	}
	n, valid := cfgParseInt(value)
	if !valid {
		a.add("server.properties", sprReasonBadValue, key+" 不是合法整数: "+value, false)
		return 0, false
	}
	return n, true
}

func sprCheckViewDistance(a *PropertiesBudgetAudit, props sprProperties) {
	view, hasView := sprCheckInt(a, props, "view-distance")
	simulation, hasSimulation := sprCheckInt(a, props, "simulation-distance")
	if hasView {
		if view > sprMaxViewDistance {
			a.add("server.properties", sprReasonViewLarge, fmt.Sprintf("view-distance=%d 超过 %d，区块与实体负载放大", view, sprMaxViewDistance), false)
		}
		if view < sprMinViewDistance {
			a.add("server.properties", sprReasonViewSmall, fmt.Sprintf("view-distance=%d 低于 %d", view, sprMinViewDistance), false)
		}
	}
	if hasSimulation && hasView && simulation > view {
		a.add("server.properties", sprReasonSimDistance, fmt.Sprintf("simulation-distance=%d 大于 view-distance=%d", simulation, view), false)
	}
}
