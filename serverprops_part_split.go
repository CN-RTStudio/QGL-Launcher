package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

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
	if err := secureWriteFile(tmp, props.Marshal(), allowedFilePerm); err != nil {
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
