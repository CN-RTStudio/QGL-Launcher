package main

import (
	"fmt"

)

func (a *App) CancelDownloadList() error {
	a.downloadMutex.Lock()
	defer a.downloadMutex.Unlock()
	if !a.isDownloading || a.downloadCancel == nil {
		return fmt.Errorf("当前没有正在进行的下载")
	}
	close(a.downloadCancel)
	return nil
}

// downloadJavaItem 下载 Java：优先通过 Mojang 官方 java-runtime 清单下载免安装运行时
// （参考 PCL，官方源 + BMCLAPI 镜像，32 线程并发，装到 <minecraftDir>/runtime/）；
// 清单中没有该版本（如 Java 26）或下载失败时，回退到 Oracle 安装包
