package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

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
func validateBoolProperty(v string) error {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "false":
		return nil
	default:
		return fmt.Errorf("布尔配置只允许 true/false，收到 %q", v)
	}
}

const maxPropertyKeyLen = 256

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
