package main

import (

)

func (a *App) downloadJavaItem(majorVer int, url string) error {
	if err := a.downloadJavaRuntime(majorVer); err != nil {
		a.writeLog("Mojang 运行时下载 Java %d 失败: %v，回退 Oracle 安装包", majorVer, err)
		return a.downloadJavaOracleInstaller(majorVer, url)
	}
	return nil
}

// downloadJavaOracleInstaller 回退方案：下载 Oracle 安装包并运行
