package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func (a *App) downloadModItem(item *DownloadItem) error {
	// 纵深防御：即便下载队列项被内部其它路径污染，落盘目录也必须在 .minecraft 内。
	mcDir := a.GetMinecraftDir()
	destDir := item.SavePath
	if destDir == "" {
		destDir = filepath.Join(mcDir, "mods")
	} else if _, ok := PathWithin(mcDir, destDir); !ok {
		return fmt.Errorf("Mod 保存路径越界，必须位于 .minecraft 目录内: %s", destDir)
	}

	if err := ensurePrivateDir(destDir); err != nil {
		return fmt.Errorf("创建 mods 目录失败: %w", err)
	}

	// 落盘名必须与入队时一致地走 nameguard：item.CustomName 在 AddModToDownloadList
	// 已由 PickSafeModFileName 净化，这里再强制一次（防队列项被其它内部路径污染），
	// 失败再退回 URL 末段，仍不行用固定安全名。
	fileName, whyName := SafeModFileName(filepath.Base(item.CustomName))
	if whyName != nameRejectNone {
		fileName = PickSafeModFileName(filepath.Base(item.URL))
	}

	// 同目录大小写 / 尾点空格碰撞唯一化：NTFS 大小写不敏感，目录里已有的
	// "Sodium.jar" 与本次 "sodium.jar" 指向同一文件。绝不能再像旧实现那样
	// “目标已存在就静默 return”——那会让用户以为装上了哈希校验过的新 Mod，
	// 实际加载的是目录里未经验证的旧 / 恶意 jar。改为自动避让改名并记安全事件。
	plannedName, collided, planErr := planModDestName(destDir, fileName)
	if planErr != nil {
		return planErr
	}
	if collided {
		recordSecurityEvent("download", auditSeverityWarn, auditActionDetected,
			"mod-name-collision", "目录内已存在大小写/尾点等价的同名 Mod，已改名避让: "+fileName+" -> "+plannedName)
	}
	fileName = plannedName

	destPath := filepath.Join(destDir, fileName)

	a.emitProgress("downloading", fileName, 0, 0)

	// 安全校验：下载 URL 必须是 HTTPS 且主机在 Mod 下载白名单内。
	if err := validateModDownloadURL(item.URL); err != nil {
		return err
	}

	// 下载结束（成功或失败）后清掉期望值，避免随下载历史无限堆积。
	defer modExpect.delete(item.URL)

	// 先尝试镜像源，失败再回退到官方源。
	// 用专用下载客户端：无 30s 总超时（大 Mod 慢网不该被整体掐断），
	// 且重定向每一跳都强制主机白名单，防镜像把流量甩到任意外部主机。
	mirrorURL := rewriteModMirrorURL(item.URL)
	if err := validateModDownloadURL(mirrorURL); err != nil {
		return fmt.Errorf("镜像下载地址不安全: %w", err)
	}
	client := newModDownloadClient()
	resp, err := client.Get(mirrorURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		resp, err = newModDownloadClient().Get(item.URL)
		if err != nil {
			// 下载台账：传输失败也要留痕（来源 / 文件名 / 失败结局）。
			a.RecordDownloadEntry(item.URL, ledgerHostOf(item.URL), fileName, "", "", LedgerStatusFailed, -1)
			return fmt.Errorf("下载 Mod 失败: %v", err)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		a.RecordDownloadEntry(item.URL, ledgerHostOf(item.URL), fileName, "", "", LedgerStatusFailed, -1)
		return fmt.Errorf("下载 Mod 失败: HTTP %d", resp.StatusCode)
	}

	// 关键：用 Modrinth 给的 Size 做一道硬上限；ContentLength 不可信（chunked 时是 -1）。
	// MaxBytesReader 多写一字节就报错，防恶意镜像返回无限流。
	_, wantSize, _ := modExpect.lookup(item.URL)
	effectiveCap := int64(maxDownloadBytes)
	if wantSize > 0 {
		// 允许比声明稍大一点（Modrinth 的 Size 本身就是文件大小，理论上严格相等，
		// 这里给 1% 余量防止 CDN 加多字节尾部但哈希仍对的极端情况）
		effectiveCap = wantSize + wantSize/100 + 1024
	}
	resp.Body = http.MaxBytesReader(nil, resp.Body, effectiveCap)

	partPath := destPath + ".part"
	out, err := openSecurePartFile(partPath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}

	// 实时磁盘守卫：chunked 响应没有可信 ContentLength，effectiveCap 只能按声明大小
	// 兜底；这里按落盘目录的真实剩余空间逐块累计实际写入，一旦会击穿安全水位立刻停写
	// 并删除残片。探测失败（unknown）时守卫停用，绝不误杀正常下载。
	startAvail := diskAvailUnknown
	if availBytes, availErr := availableDiskBytes(filepath.Dir(partPath)); availErr == nil {
		startAvail = availBytes
	}
	diskGuard := newDiskWriteGuard(startAvail, 0)

	total := resp.ContentLength
	var downloaded int64
	buf := make([]byte, 32*1024)

	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if ok, _ := diskGuard.recordChunk(int64(n)); !ok {
				out.Close()
				os.Remove(partPath)
				recordSecurityEvent("download", auditSeverityCritical, auditActionBlocked,
					"disk-space", describeDiskWriteAbort(diskGuard))
				return fmt.Errorf("%s", describeDiskWriteAbort(diskGuard))
			}
			if _, werr := out.Write(buf[:n]); werr != nil {
				out.Close()
				os.Remove(partPath)
				return werr
			}
			downloaded += int64(n)
			a.emitProgress("downloading", fileName, downloaded, total)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			out.Close()
			os.Remove(partPath)
			return readErr
		}
	}
	out.Close()

	// 关键：下载完先用 Modrinth 给的哈希 + Size 校验，再原子改名，
	// 两者都拒绝顺着预置符号链接写穿到 mods 目录之外。
	if err := verifyModDownloaded(partPath, item.URL); err != nil {
		os.Remove(partPath)
		// 下载台账：哈希校验不通过 = 潜在供应链异常，critical 留痕。
		a.RecordDownloadEntry(item.URL, ledgerHostOf(item.URL), fileName, "", "", LedgerStatusMismatch, wantSize)
		return fmt.Errorf("Mod 完整性校验失败: %w", err)
	}

	// 哈希只能证明“和源站声明一致”，证明不了作者上传的内容无害。落定成
	// 最终 jar（即将随 JVM 加载）前做静态内容扫描：根目录可执行载荷、损坏
	// 压缩包等 critical 项直接阻止安装；warn/info 只记审计不阻断。
	if _, err := enforceModJarScan(partPath, "mod-download", fileName); err != nil {
		os.Remove(partPath)
		return fmt.Errorf("Mod 安全扫描失败: %w", err)
	}
	if err := finalizeDownloadFile(partPath, destPath); err != nil {
		return err
	}
	// 下载台账：成功落盘后记 ok（哈希算法取期望表首选，sha512 优先）。
	ledgerAlgo, ledgerHash := "", ""
	if hashes, _, ok := modExpect.lookup(item.URL); ok {
		if v, ok := hashes["sha512"]; ok {
			ledgerAlgo, ledgerHash = "sha512", v
		} else if v, ok := hashes["sha1"]; ok {
			ledgerAlgo, ledgerHash = "sha1", v
		}
	}
	a.RecordDownloadEntry(item.URL, ledgerHostOf(item.URL), fileName, ledgerAlgo, ledgerHash, LedgerStatusOK, wantSize)
	return nil
}

// GetModrinthCategories 获取 Modrinth 分类标签
func (a *App) GetModrinthCategories() ([]ModCategory, error) {
	apiURL := fmt.Sprintf("%s/tag/category", modrinthBaseURL)

	client := safeHTTPClient()
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("获取分类失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取分类失败: HTTP %d", resp.StatusCode)
	}

	var categories []ModCategory
	if err := readAPIJSON(resp, &categories); err != nil {
		return nil, fmt.Errorf("解析分类失败: %v", err)
	}

	modCategories := []ModCategory{}
	for _, cat := range categories {
		if cat.ProjectType == "mod" {
			modCategories = append(modCategories, cat)
		}
	}

	return modCategories, nil
}
