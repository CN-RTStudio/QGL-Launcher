package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Keys 返回所有键（排序），主要用于测试与排查。
func (p *serverProperties) Keys() []string {
	seen := map[string]bool{}
	var keys []string
	for _, ln := range p.lines {
		if ln.isPair && !seen[ln.key] {
			seen[ln.key] = true
			keys = append(keys, ln.key)
		}
	}
	sort.Strings(keys)
	return keys
}

// updateServerProperty 以保序方式更新 server.properties 中的单个键并原子落盘。
// valueValidator 非空时用于校验待写入的值（防配置注入）；文件不存在时返回错误。
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
	if err := os.WriteFile(tmp, props.Marshal(), allowedFilePerm); err != nil {
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

// writeInitialServerProperties 用统一的安全读写器创建首份 server.properties，
// 替代旧实现里 fmt.Sprintf 裸拼文本的写法。server-port / online-mode / motd 全部经
// 键名 / 单行值校验，motd 再单独过展示名规则；先写 .tmp 再 rename，绝不留半成品。
func writeInitialServerProperties(path string, port int, onlineMode bool, motd string) error {
	if !isValidPort(port) {
		return fmt.Errorf("端口号无效: %d", port)
	}
	if err := validateServerMotd(motd); err != nil {
		return err
	}
	props := &serverProperties{}
	props.Set("server-port", strconv.Itoa(port))
	props.Set("online-mode", strconv.FormatBool(onlineMode))
	props.Set("motd", motd)

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, props.Marshal(), allowedFilePerm); err != nil {
		return fmt.Errorf("写入临时配置失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("替换 server.properties 失败: %w", err)
	}
	return nil
}

// validateBoolProperty 只接受 Properties 语义里的真假值，拒绝夹带换行或额外内容。
func validateBoolProperty(v string) error {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "false":
		return nil
	default:
		return fmt.Errorf("布尔配置只允许 true/false，收到 %q", v)
	}
}

// maxPropertyKeyLen 限制单个配置键长度，正常 server.properties 键远小于此。
const maxPropertyKeyLen = 256

// validatePropertyKey 校验配置键只含 java.util.Properties 实际可用的标识字符
// （字母数字与 . _ -），拒绝空白、分隔符（= :，会被解析成键值边界）、换行与任何
// 控制字符，从源头杜绝借键名注入。
func validatePropertyKey(key string) error {
	if key == "" {
		return fmt.Errorf("配置键为空")
	}
	if len(key) > maxPropertyKeyLen {
		return fmt.Errorf("配置键过长")
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			continue
		case c == '.' || c == '_' || c == '-':
			continue
		default:
			return fmt.Errorf("配置键含非法字符 %q", c)
		}
	}
	return nil
}

// validatePropertyValueSingleLine 强制配置值不得跨行：拒绝 CR/LF（可注入新键）、
// NUL 与其它 ASCII 控制字符，并给一个与配置读取一致的长度上限。
func validatePropertyValueSingleLine(value string) error {
	if len(value) > maxServerLogLineBytes {
		return fmt.Errorf("配置值过长")
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '\n' || c == '\r' {
			return fmt.Errorf("配置值不允许跨行")
		}
		if c == 0x00 || (c < 0x20 && c != '\t') || c == 0x7f {
			return fmt.Errorf("配置值含控制字符")
		}
	}
	return nil
}
