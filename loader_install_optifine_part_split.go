package main

import (
	"fmt"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"strings"
)

func (a *App) AddLoaderToDownloadList(loaderName string, mcVersion string, loaderVersion string, downloadURL string) error {
	// 三个标识全部来自前端，最终拼进下载列表展示名并参与安装分发，必须收敛：
	// loaderName 走固定白名单（它决定后续 switch 分支），mc/loader 版本走严格名单段。
	loaderName = strings.ToLower(strings.TrimSpace(loaderName))
	switch loaderName {
	case "forge", "fabric", "neoforge", "optifine":
	default:
		return fmt.Errorf("不支持的加载器类型: %s", loaderName)
	}
	safeMC, whyM := SafeVersionComponent(mcVersion)
	if whyM != nameRejectNone {
		return fmt.Errorf("Minecraft 版本无效: %s", describeNameReject(whyM))
	}
	mcVersion = safeMC
	safeLV, whyL := SafeLoaderComponent(loaderVersion)
	if whyL != nameRejectNone {
		return fmt.Errorf("加载器版本无效: %s", describeNameReject(whyL))
	}
	loaderVersion = safeLV
	customName := fmt.Sprintf("%s %s (%s)", loaderName, loaderVersion, mcVersion)
	if safeName, why := SafeVersionDisplayName(customName); why != nameRejectNone {
		return fmt.Errorf("加载器任务名称无效: %s", describeNameReject(why))
	} else {
		customName = safeName
	}
	// 下载地址来自前端，最终会"下载即运行"第三方安装器：入队时就先把非 HTTPS
	// 链接挡掉，避免恶意 / 被劫持的明文地址进入队列后才在下载阶段暴露。
	// 空地址交给下载阶段统一报错（个别加载器走内置安装器路径时可能不带 URL）。
	if strings.TrimSpace(downloadURL) != "" && !isHTTPSURL(downloadURL) {
		return fmt.Errorf("不支持的加载器下载地址（仅允许 HTTPS）")
	}

	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()

	pending := DownloadItem{
		ID:         fmt.Sprintf("loader-%s-%s", loaderName, loaderVersion),
		URL:        downloadURL,
		CustomName: customName,
		Type:       "loader",
		ItemType:   "loader",
		Status:     "pending",
		Progress:   0,
	}
	if why := auditDownloadItemForEnqueue(a.downloadList, pending); why != dqRejectNone {
		return fmt.Errorf("%s", describeQueueReject(why))
	}
	if why := auditDownloadItemFields(pending, a.GetMinecraftDir()); why != dfRejectNone {
		return fmt.Errorf("%s", describeDownloadFieldReject(why))
	}

	a.downloadList = append(a.downloadList, pending)

	runtime.EventsEmit(a.ctx, "downloadListUpdated", a.downloadList)
	return nil
}
