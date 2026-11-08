package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) GetGlobalConfig() (*GlobalConfig, error) {
	configPath := filepath.Join(a.GetQGLDir(), "config.json")
	var config GlobalConfig
	if err := readPrivateStoreJSON(configPath, &config, "全局配置"); err != nil {
		if os.IsNotExist(err) {
			return &GlobalConfig{}, nil
		}
		return nil, fmt.Errorf("读取全局配置失败: %w", err)
	}
	if err := validateLoadedGlobalConfig(&config); err != nil {
		return nil, fmt.Errorf("全局配置不安全: %w", err)
	}
	return &config, nil
}

func (a *App) SaveGlobalConfig(config *GlobalConfig) error {
	qglDir := a.GetQGLDir()
	if err := os.MkdirAll(qglDir, 0700); err != nil {
		return fmt.Errorf("创建QGL目录失败: %w", err)
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化全局配置失败: %w", err)
	}
	configPath := filepath.Join(qglDir, "config.json")
	// 安全加固: 全局配置原子写、0600、拒绝符号链接写穿
	if err := secureWritePrivateFile(configPath, data); err != nil {
		return fmt.Errorf("写入全局配置失败: %w", err)
	}
	// 本进程可信写入后刷新防篡改基线（用户 UI 主动改配置不应被误判为外部篡改）。
	a.UpdateConfigGuardBaseline(a.configSnapshotOf(config, nil))
	return nil
}

func (a *App) GetUserConfig(username string) (*UserConfig, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	configPath := filepath.Join(a.GetUsersDir(), username, "config.json")
	var config UserConfig
	if err := readPrivateStoreJSON(configPath, &config, "用户配置"); err != nil {
		if os.IsNotExist(err) {
			return &UserConfig{}, nil
		}
		return nil, fmt.Errorf("读取用户配置失败: %w", err)
	}
	if err := validateLoadedUserConfig(&config); err != nil {
		return nil, fmt.Errorf("用户配置不安全: %w", err)
	}
	return &config, nil
}

func (a *App) SaveUserConfig(username string, config *UserConfig) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	userDir := filepath.Join(a.GetUsersDir(), username)
	if err := os.MkdirAll(userDir, 0700); err != nil {
		return fmt.Errorf("创建用户目录失败: %w", err)
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化用户配置失败: %w", err)
	}
	configPath := filepath.Join(userDir, "config.json")
	// 安全加固: 用户配置原子写、0600、拒绝符号链接写穿
	if err := secureWritePrivateFile(configPath, data); err != nil {
		return fmt.Errorf("写入用户配置文件失败: %w", err)
	}
	// 版本选择属启动执行目标类字段，本进程可信写入后同步刷新防篡改基线。
	if g, err := a.GetGlobalConfig(); err == nil {
		a.UpdateConfigGuardBaseline(a.configSnapshotOf(g, config))
	}
	return nil
}

func (a *App) IsVersionIsolation() bool {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return false
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		return false
	}
	return config.VersionIsolation
}

func (a *App) SetVersionIsolation(enabled bool) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("获取当前用户失败: %w", err)
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		return fmt.Errorf("读取用户配置失败: %w", err)
	}
	config.VersionIsolation = enabled
	return a.SaveUserConfig(currentUser.Username, config)
}

func (a *App) GetSelectedVersion() string {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return ""
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		return ""
	}
	return config.SelectedVersion
}

func (a *App) SetSelectedVersion(versionID string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	// versionID 随后会拼进 versions/<id> 路径，必须按单段安全路径名收口，
	// 拒绝 "../"、分隔符、保留设备名与控制字符，防止配置投毒演变成路径穿越。
	safeID, reason := SafeVersionID(versionID)
	if reason != configRejectNone {
		recordSecurityEvent(auditCategoryConfig, auditSeverityWarn, auditActionRejected,
			"SetSelectedVersion", "拒绝非法版本ID: "+reason)
		return fmt.Errorf("无效的版本标识: %s", reason)
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		config = &UserConfig{}
	}
	config.SelectedVersion = safeID
	return a.SaveUserConfig(currentUser.Username, config)
}

// GetThemeColor 获取当前用户的主题色
func (a *App) GetThemeColor() string {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return "cyan"
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil || config.ThemeColor == "" {
		return "cyan"
	}
	return config.ThemeColor
}

// SetThemeColor 设置当前用户的主题色
func (a *App) SetThemeColor(color string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	// 主题色会被前端读回用于 data-theme / 样式键，落盘前强制白名单，
	// 拒绝未知值与夹带控制字符 / 标记的配置投毒。
	safeColor, reason := SafeThemeColor(color)
	if reason != configRejectNone {
		recordSecurityEvent(auditCategoryConfig, auditSeverityWarn, auditActionRejected,
			"SetThemeColor", "拒绝非法主题色: "+reason)
		return fmt.Errorf("无效的主题色: %s", reason)
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		config = &UserConfig{}
	}
	config.ThemeColor = safeColor
	err = a.SaveUserConfig(currentUser.Username, config)
	if err != nil {
		return err
	}
	runtime.EventsEmit(a.ctx, "themeChanged", safeColor)
	return nil
}

// GetShowExportLaunchCommand 获取是否显示导出启动命令按钮
func (a *App) GetShowExportLaunchCommand() bool {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return false
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		return false
	}
	return config.ShowExportLaunchCommand
}

// SetShowExportLaunchCommand 设置是否显示导出启动命令按钮
func (a *App) SetShowExportLaunchCommand(show bool) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		config = &UserConfig{}
	}
	config.ShowExportLaunchCommand = show
	return a.SaveUserConfig(currentUser.Username, config)
}

// GetBackgroundImage 获取当前用户的背景图片路径
func (a *App) GetBackgroundImage() string {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return ""
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		return ""
	}
	return config.BackgroundImage
}

// allowedBackgroundRoots 列出允许作为背景图来源的根目录。
func (a *App) allowedBackgroundRoots() []string {
	roots := []string{filepath.Join(a.GetQGLDir(), "cache")}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots,
			filepath.Join(home, "Pictures"),
			filepath.Join(home, "Videos"),
		)
	}
	return roots
}

// isSafeBackgroundPath 校验背景图片路径：
//  1. 文件必须存在且是普通文件；
//  2. 扩展名必须是图片类型（走 sanitize.go 的白名单）；
//  3. 路径不能是符号链接；
//  4. 路径必须落在 QGL/cache 或用户 Pictures/Videos 目录下。
func (a *App) isSafeBackgroundPath(p string) bool {
	if p == "" || IsSymlink(p) {
		return false
	}
	info, err := os.Stat(p)
	if err != nil || info.IsDir() || info.Size() > maxBackgroundImageBytes {
		return false
	}
	if !IsSafeImageExt(p) {
		return false
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	for _, root := range a.allowedBackgroundRoots() {
		if _, ok := PathWithin(root, abs); ok {
			return true
		}
	}
	return false
}

// SetBackgroundImage 设置当前用户的背景图片路径
func (a *App) SetBackgroundImage(path string) error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("未登录")
	}
	// 安全加固：不接受任意路径，只能是 Pictures/Videos 或 QGL/cache 下的图片
	if !a.isSafeBackgroundPath(path) {
		return fmt.Errorf("背景图片路径不安全或不在允许目录内")
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		config = &UserConfig{}
	}
	config.BackgroundImage = path
	err = a.SaveUserConfig(currentUser.Username, config)
	if err != nil {
		return err
	}
	runtime.EventsEmit(a.ctx, "backgroundChanged", path)
	return nil
}

// SelectBackgroundImage 打开文件选择对话框选择背景图片
func (a *App) SelectBackgroundImage() (string, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择背景图片",
		Filters: []runtime.FileFilter{
			{DisplayName: "图片文件", Pattern: "*.jpg;*.jpeg;*.png;*.bmp;*.webp"},
		},
	})
	if err != nil {
		return "", err
	}
	return path, nil
}

// GetBackgroundImageDataURL 获取背景图片的 base64 Data URL（用于 CSS background-image）
func (a *App) GetBackgroundImageDataURL() string {
	path := a.GetBackgroundImage()
	if path == "" || !fileExists(path) {
		return ""
	}
	// 安全加固：即使 config 里残留了老路径，读之前再校一遍
	if !a.isSafeBackgroundPath(path) {
		return ""
	}
	url, err := a.fileToDataURL(path)
	if err != nil {
		return ""
	}
	return url
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// GetBingDailyImage 获取 Bing 每日壁纸图片
// 1. 请求 Bing API 获取重定向 URL
// 2. 跟随重定向获取实际图片
// 3. 缓存到本地并返回 data URL
func (a *App) GetBingDailyImage() (string, error) {
	cacheDir := filepath.Join(a.GetQGLDir(), "cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return "", fmt.Errorf("创建缓存目录失败: %w", err)
	}
	cachePath := filepath.Join(cacheDir, "bing_daily.jpg")
	// 请求 Bing API（会重定向到图片 URL）
	client := safeHTTPClient()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// 不自动跟随重定向，我们需要获取最终的图片 URL
		return http.ErrUseLastResponse
	}
	resp, err := client.Get("https://bing.biturl.top/?resolution=1920&format=image&index=0&mkt=zh-CN")
	if err != nil {
		return "", fmt.Errorf("请求 Bing API 失败: %w", err)
	}
	defer resp.Body.Close()
	// 获取最终图片 URL（从 Location 头或响应体中）
	imageURL := ""
	if resp.StatusCode == 302 || resp.StatusCode == 301 || resp.StatusCode == 307 || resp.StatusCode == 308 {
		imageURL = resp.Header.Get("Location")
	} else if resp.StatusCode == 200 {
		// 有些 API 直接返回图片，限 10MB 防超大 body
		limited := io.LimitReader(resp.Body, maxBackgroundImageBytes)
		data, err := io.ReadAll(limited)
		if err != nil {
			return "", fmt.Errorf("读取响应失败: %w", err)
		}
		if len(data) >= maxBackgroundImageBytes {
			return "", fmt.Errorf("Bing 图片过大，已拒绝")
		}
		if err := secureWritePrivateFile(cachePath, data); err != nil {
			return "", fmt.Errorf("缓存图片失败: %w", err)
		}
		return a.fileToDataURL(cachePath)
	}
	if imageURL == "" {
		return "", fmt.Errorf("未获取到图片地址，状态码: %d", resp.StatusCode)
	}
	// 安全加固: 用 ValidateURL 统一校验
	if !ValidateURL(imageURL) {
		return "", fmt.Errorf("无效的图片 URL 协议")
	}
	// 下载实际图片
	imgResp, err := safeHTTPClient().Get(imageURL)
	if err != nil {
		return "", fmt.Errorf("下载图片失败: %w", err)
	}
	defer imgResp.Body.Close()
	if imgResp.StatusCode != 200 {
		return "", fmt.Errorf("下载失败，状态码: %d", imgResp.StatusCode)
	}
	// 限 10MB，防止恶意 CDN 塞个多 G 文件
	limited := io.LimitReader(imgResp.Body, maxBackgroundImageBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", fmt.Errorf("读取图片数据失败: %w", err)
	}
	if len(data) >= maxBackgroundImageBytes {
		return "", fmt.Errorf("图片过大，已拒绝")
	}
	// 缓存到本地（原子写，防止预置符号链接把图片数据写穿到其它文件）
	if err := secureWritePrivateFile(cachePath, data); err != nil {
		return "", fmt.Errorf("缓存图片失败: %w", err)
	}
	// 设置为当前背景
	a.SetBackgroundImage(cachePath)
	return a.fileToDataURL(cachePath)
}

// GetCachedBingImage 获取缓存的 Bing 图片（如果存在）
func (a *App) GetCachedBingImage() string {
	cachePath := filepath.Join(a.GetQGLDir(), "cache", "bing_daily.jpg")
	if !fileExists(cachePath) {
		return ""
	}
	url, _ := a.fileToDataURL(cachePath)
	return url
}

func (a *App) fileToDataURL(path string) (string, error) {
	// 走统一的有界读取原语：stat 声明拦截 + LimitReader+1 兜底 + 拒绝符号链接/特殊文件，
	// 防止背景图被换成设备/管道或塞成超大文件把进程内存打爆。
	data, err := readBoundedFile(path, maxBackgroundDataURLBytes)
	if err != nil {
		return "", err
	}
	ext := strings.ToLower(filepath.Ext(path))
	mimeMap := map[string]string{
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".bmp":  "image/bmp",
		".webp": "image/webp",
	}
	mimeType := mimeMap[ext]
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	b64 := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("data:%s;base64,%s", mimeType, b64), nil
}
