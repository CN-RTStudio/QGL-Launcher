package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) emitFixProgress(step string, done, total int64) {
	a.emitProgress("downloading", step, done, total)
	runtime.EventsEmit(a.ctx, "launchFixProgress", step)
}

// formatBytesForProgress 将字节数格式化为 MB 显示（进度步骤文本用）
func formatBytesForProgress(b int64) string {
	return fmt.Sprintf("%.1f MB", float64(b)/1024/1024)
}

// downloadFileMultiThread 多线程分段下载单个文件（参考补全文件的并发思路）
// 通过 HTTP Range 将文件分成 threads 段并行下载；服务器不支持 Range 时自动回退单线程
// 进度通过 emitProgress 上报（文件名 + 已下载字节/总字节），total<=0 时步骤文本显示已下载量
func (a *App) downloadFileMultiThread(url string, destPath string, threads int) error {
	if threads < 1 {
		threads = 8
	}
	os.MkdirAll(filepath.Dir(destPath), 0755)

	// 已存在则跳过
	if info, err := os.Stat(destPath); err == nil && info.Size() > 0 {
		return nil
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("创建请求失败 %s: %v", url, err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.216 CosyBrowser/146.3.1")

	client := &http.Client{Timeout: 30 * time.Second}
	// 先发 HEAD/Range 探测：获取总大小与是否支持分段
	probe, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("下载失败 %s: %v", url, err)
	}
	if probe.StatusCode != http.StatusOK {
		probe.Body.Close()
		return fmt.Errorf("下载失败 %s: HTTP %d", url, probe.StatusCode)
	}
	total := probe.ContentLength
	acceptRanges := probe.Header.Get("Accept-Ranges")
	probe.Body.Close()

	name := filepath.Base(destPath)
	if total <= 0 || !strings.EqualFold(acceptRanges, "bytes") {
		// 服务器不支持分段或大小未知 → 单线程流式下载
		return a.downloadFileStream(url, destPath, name, total)
	}

	// 分段并行下载到临时文件，最后合并
	partDir := destPath + ".qglparts"
	os.RemoveAll(partDir)
	os.MkdirAll(partDir, 0755)
	defer os.RemoveAll(partDir)

	segmentSize := total / int64(threads)
	type segment struct {
		index int64
		start int64
		end   int64
	}
	segments := make([]segment, 0, threads)
	var start int64
	for i := 0; i < threads; i++ {
		end := start + segmentSize - 1
		if i == threads-1 {
			end = total - 1
		}
		if start > end {
			break
		}
		segments = append(segments, segment{index: int64(i), start: start, end: end})
		start = end + 1
	}

	var (
		wg        sync.WaitGroup
		downloaded int64
		mu        sync.Mutex
		firstErr  error
		lastEmit  time.Time
	)
	wg.Add(len(segments))
	for _, seg := range segments {
		seg := seg
		go func() {
			defer wg.Done()
			preq, err := http.NewRequest("GET", url, nil)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			preq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.216 CosyBrowser/146.3.1")
			preq.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", seg.start, seg.end))

			resp, err := http.DefaultClient.Do(preq)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("HTTP %d", resp.StatusCode)
				}
				mu.Unlock()
				return
			}

			partPath := filepath.Join(partDir, fmt.Sprintf("%04d.part", seg.index))
			pf, err := os.Create(partPath)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			defer pf.Close()

			buf := make([]byte, 64*1024)
			for {
				n, readErr := resp.Body.Read(buf)
				if n > 0 {
					if _, werr := pf.Write(buf[:n]); werr != nil {
						mu.Lock()
						if firstErr == nil {
							firstErr = werr
						}
						mu.Unlock()
						return
					}
					atomic.AddInt64(&downloaded, int64(n))
					// 进度上报（加锁避免时间戳竞争，200ms 节流）
					mu.Lock()
					if time.Since(lastEmit) > 200*time.Millisecond {
						lastEmit = time.Now()
						dl := atomic.LoadInt64(&downloaded)
						mu.Unlock()
						a.emitProgress("downloading", fmt.Sprintf("%s %s/%s (%d%%)", name, formatBytesForProgress(dl), formatBytesForProgress(total), dl*100/total), dl, total)
						continue
					}
					mu.Unlock()
				}
				if readErr == io.EOF {
					return
				}
				if readErr != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = readErr
					}
					mu.Unlock()
					return
				}
			}
		}()
	}
	wg.Wait()

	if firstErr != nil {
		return fmt.Errorf("下载失败 %s: %v", url, firstErr)
	}

	// 合并分段文件
	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("创建文件失败 %s: %v", destPath, err)
	}
	defer out.Close()
	for _, seg := range segments {
		partPath := filepath.Join(partDir, fmt.Sprintf("%04d.part", seg.index))
		pf, err := os.Open(partPath)
		if err != nil {
			return fmt.Errorf("合并分段失败: %v", err)
		}
		_, err = io.Copy(out, pf)
		pf.Close()
		if err != nil {
			return fmt.Errorf("合并分段失败: %v", err)
		}
	}
	a.emitProgress("downloading", name, total, total)
	return nil
}

// downloadFileStream 单线程流式下载（多线程的回退路径），带进度
func (a *App) downloadFileStream(url string, destPath string, name string, total int64) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("创建请求失败 %s: %v", url, err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.216 CosyBrowser/146.3.1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("下载失败 %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败 %s: HTTP %d", url, resp.StatusCode)
	}
	if resp.ContentLength > 0 {
		total = resp.ContentLength
	}

	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("创建文件失败 %s: %v", destPath, err)
	}
	defer out.Close()

	var downloaded int64
	buf := make([]byte, 64*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
			downloaded += int64(n)
			if total > 0 {
				a.emitProgress("downloading", fmt.Sprintf("%s %s/%s (%d%%)", name, formatBytesForProgress(downloaded), formatBytesForProgress(total), downloaded*100/total), downloaded, total)
			} else {
				// 总大小未知（如 chunked 传输）：进度条保持 0，步骤文本显示已下载量
				a.emitProgress("downloading", fmt.Sprintf("%s %s", name, formatBytesForProgress(downloaded)), 0, 0)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	return nil
}

// downloadFile 下载文件到指定路径
func (a *App) downloadFile(url string, destPath string, reportProgress bool) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败 %s: %v", dir, err)
	}

	// 如果文件已存在，跳过下载
	if info, err := os.Stat(destPath); err == nil && info.Size() > 0 {
		return nil
	}

	// 创建请求并添加 User-Agent（避免 BMCLAPI 403 拦截）
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("创建请求失败 %s: %v", url, err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.216 CosyBrowser/146.3.1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("下载失败 %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败 %s: HTTP %d", url, resp.StatusCode)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("创建文件失败 %s: %v", destPath, err)
	}
	defer out.Close()

	if reportProgress {
		total := resp.ContentLength
		var downloaded int64
		buf := make([]byte, 32*1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				_, werr := out.Write(buf[:n])
				if werr != nil {
					return werr
				}
				downloaded += int64(n)
				a.emitProgress("downloading", filepath.Base(destPath), downloaded, total)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
	} else {
		_, err = io.Copy(out, resp.Body)
		if err != nil {
			return fmt.Errorf("写入文件失败 %s: %v", destPath, err)
		}
	}

	return nil
}

// GetVersionManifest 获取版本清单，优先使用 BMCLAPI，失败回退 Mojang
func (a *App) GetVersionManifest() ([]MCVersion, error) {
	urls := []string{
		"https://bmclapi2.bangbang93.com/mc/game/version_manifest_v2.json",
		"https://piston-meta.mojang.com/mc/game/version_manifest_v2.json",
	}

	var body []byte
	var lastErr error

	for _, u := range urls {
		resp, err := http.Get(u)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, u)
			continue
		}

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			continue
		}
		lastErr = nil
		break
	}

	if lastErr != nil {
		return nil, fmt.Errorf("获取版本清单失败: %v", lastErr)
	}

	var manifest VersionManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, fmt.Errorf("解析版本清单失败: %v", err)
	}

	var result []MCVersion
	for _, v := range manifest.Versions {
		if v.Type == "release" || v.Type == "snapshot" {
			result = append(result, MCVersion{
				ID:          v.ID,
				Type:        v.Type,
				URL:         v.URL,
				ReleaseTime: v.ReleaseTime,
			})
		}
	}

	return result, nil
}

// GetInstalledVersions 获取已安装的版本列表（仅读取，不扫描创建 config.json）
