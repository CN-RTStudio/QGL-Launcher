package main

import (
	"fmt"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

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
