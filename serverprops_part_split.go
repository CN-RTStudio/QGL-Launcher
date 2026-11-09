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
