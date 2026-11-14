package main

import (
	"fmt"
	"os"
	"strings"
)

func updateServerProperty(path, key, value string, valueValidator func(string) error) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("配置键不能为空")
	}
	// 键名 / 单行值的净化是“无条件”的底线：即使调用方忘了传 valueValidator，也绝不
	// 允许借 properties 文本注入新行（value 里塞 "\nmalicious=true" 会被解析成新键），
	// 也不允许出现 java.util.Properties 键名字符集之外的内容。
	if err := validatePropertyKey(key); err != nil {
		return fmt.Errorf("配置键不合法: %w", err)
	}
	if err := validatePropertyValueSingleLine(value); err != nil {
		return fmt.Errorf("配置值不合法: %w", err)
	}
	if valueValidator != nil {
		if err := valueValidator(value); err != nil {
			return fmt.Errorf("配置值不合法: %w", err)
		}
	}
	// server.properties 是“读进内存再改写回盘”的纯文本配置，走 64MiB 有界读取，
	// 防止被塞成超大文件时整体读入 OOM；写入仍保持 allowedFilePerm 共享权限不变。
	data, err := readBoundedFile(path, localTextConfigMaxBytes)
	if err != nil {
		return fmt.Errorf("读取 server.properties 失败: %w", err)
	}
	props := parseServerProperties(data)
	props.Set(key, value)

	tmp := path + ".tmp"
	if err := secureWriteFile(tmp, props.Marshal(), allowedFilePerm); err != nil {
		return fmt.Errorf("写入临时配置失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("替换 server.properties 失败: %w", err)
	}
	return nil
}

// maxServerNameLen 服务器展示名 / motd 的长度上限。
// 名称会同时进目录名（customDir 缺省时）与 server.properties 的 motd，必须给完整路径
// 与单行配置留余量，取 120。
const maxServerNameLen = 120

// validateServerMotd 校验写入 server.properties 的 motd 值：
// 复用单行值规则（拒 CR/LF / 控制字符，长度上限），motd 允许空格与中文等普通可见字符，
// 但绝不允许借换行注入新的配置键。
func validateServerMotd(v string) error {
	if v == "" {
		return fmt.Errorf("motd 不能为空")
	}
	if len(v) > maxServerNameLen {
		return fmt.Errorf("motd 超过 %d 字符上限", maxServerNameLen)
	}
	return validatePropertyValueSingleLine(v)
}
