package main

import (

)

func (a *App) GetBackgroundImage() string {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return ""
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		return ""
	}
	return config.BackgroundImage
}

// SetBackgroundImage 设置当前用户的背景图片路径
