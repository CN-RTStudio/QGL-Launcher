package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

func validateLoadedGlobalConfig(cfg *GlobalConfig) error {
	if cfg == nil {
		return fmt.Errorf("全局配置为空")
	}
	if cfg.CurrentUser != "" {
		if err := validateUsername(cfg.CurrentUser); err != nil {
			return fmt.Errorf("全局配置中的当前用户名非法: %w", err)
		}
	}
	if cfg.MinecraftDir != "" {
		dir := strings.TrimSpace(cfg.MinecraftDir)
		if dir == "" {
			return fmt.Errorf("全局配置中的 Minecraft 目录为空白")
		}
		if containsControlByte(dir) || strings.ContainsRune(dir, 0) {
			return fmt.Errorf("全局配置中的 Minecraft 目录包含控制字符")
		}
		cleaned := filepath.Clean(dir)
		if !filepath.IsAbs(cleaned) {
			return fmt.Errorf("全局配置中的 Minecraft 目录必须是绝对路径: %q", cfg.MinecraftDir)
		}
	}
	if cfg.MaxMemory != 0 && !isValidMemory(cfg.MaxMemory) {
		return fmt.Errorf("全局配置中的最大内存越界: %d", cfg.MaxMemory)
	}
	if cfg.MinMemory != 0 && !isValidMemory(cfg.MinMemory) {
		return fmt.Errorf("全局配置中的最小内存越界: %d", cfg.MinMemory)
	}
	if cfg.MaxMemory != 0 && cfg.MinMemory != 0 && cfg.MinMemory > cfg.MaxMemory {
		return fmt.Errorf("全局配置中的最小内存不能大于最大内存")
	}
	return nil
}

func validateLoadedUserConfig(cfg *UserConfig) error {
	if cfg == nil {
		return fmt.Errorf("用户配置为空")
	}
	if safeID, reason := SafeVersionID(cfg.SelectedVersion); reason != configRejectNone {
		return fmt.Errorf("用户配置中的版本标识非法: %s", reason)
	} else {
		cfg.SelectedVersion = safeID
	}
	if trimmed := strings.TrimSpace(cfg.ThemeColor); trimmed != "" {
		if safeColor, reason := SafeThemeColor(cfg.ThemeColor); reason != configRejectNone {
			return fmt.Errorf("用户配置中的主题色非法: %s", reason)
		} else {
			cfg.ThemeColor = safeColor
		}
	}
	if cfg.BackgroundImage != "" {
		if len(cfg.BackgroundImage) > maxStoredPathLen {
			return fmt.Errorf("用户配置中的背景图路径超长")
		}
		if containsControlByte(cfg.BackgroundImage) || strings.ContainsRune(cfg.BackgroundImage, 0) {
			return fmt.Errorf("用户配置中的背景图路径包含控制字符")
		}
	}
	return nil
}
