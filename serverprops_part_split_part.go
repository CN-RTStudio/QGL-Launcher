package main

import "fmt"

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
