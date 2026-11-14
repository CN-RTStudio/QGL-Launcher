package main

import (

)

func (a *App) SetCurrentUser(id string) error {
	config, err := a.GetGlobalConfig()
	if err != nil {
		config = &GlobalConfig{}
	}
	// CurrentUser 存储用户标识（随机文件夹名）
	config.CurrentUser = id
	return a.SaveGlobalConfig(config)
}
