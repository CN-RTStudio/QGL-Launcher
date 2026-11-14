package main

import (
)

func (a *App) GetHelperMode() HelperModeState {
	config, err := a.GetGlobalConfig()
	if err != nil {
		return HelperModeState{Active: false}
	}
	return HelperModeState{
		Active: config.HelperMode && config.HelperModeDir != "",
		Dir:    config.HelperModeDir,
	}
}

// EnterHelperMode 进入辅助模式，指定 .minecraft 目录
// 之后所有下载/启动都会使用该目录（绕过 PCL/HMCL 直接安装）
