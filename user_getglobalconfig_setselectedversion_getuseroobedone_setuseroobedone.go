package main

import (

)

func (a *App) SetUserOOBEDone() error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return err
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		config = &UserConfig{}
	}
	config.OOBE = true
	return a.SaveUserConfig(currentUser.Dir, config)
}

// SetThemeColor 设置当前用户的主题色
