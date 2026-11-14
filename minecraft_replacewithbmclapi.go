package main

import (
	"strings"
	"time"

)

func replaceWithBMCLAPI(url string) string {
	url = strings.Replace(url, "https://piston-meta.mojang.com", "https://bmclapi2.bangbang93.com", 1)
	url = strings.Replace(url, "https://launcher.mojang.com", "https://bmclapi2.bangbang93.com", 1)
	url = strings.Replace(url, "https://libraries.minecraft.net", "https://bmclapi2.bangbang93.com/maven", 1)
	return url
}

// emitProgress 发送下载进度事件，同时更新下载列表中当前下载项的进度
// 高频下载时进行节流（100ms），避免事件风暴导致前端卡顿；终态（completed/failed）不节流
var lastProgressEmit time.Time

// setProgressScale 设置当前下载项的阶段进度映射：内部子进度 pct (0-100) 显示为 base + pct/100*span
// 用于把多个阶段（jar/库/资源/安装器运行等）组合成整项的总百分比，避免某阶段无进度时卡在 0%
