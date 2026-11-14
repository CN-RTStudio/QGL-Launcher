package main

import (

)

func (a *App) isVersionIsolated() bool {
	return a.IsVersionIsolation()
}

// buildClasspath 构建类路径（参考 PCL 的 McLibListGetWithJson + McLaunchArgumentsReplace）
