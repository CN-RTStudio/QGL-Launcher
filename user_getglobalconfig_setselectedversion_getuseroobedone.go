package main

import (

)

func (a *App) GetUserOOBEDone() (bool, error) {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return false, err
	}
	config, err := a.GetUserConfig(currentUser.Dir)
	if err != nil {
		return false, err
	}
	return config.OOBE, nil
}

// SetUserOOBEDone 标记当前用户的用户向导已完成
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
