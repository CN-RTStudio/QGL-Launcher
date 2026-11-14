package main

import (

)

func (a *App) GetOOBEDone() (bool, error) {
	config, err := a.GetGlobalConfig()
	if err != nil {
		return false, err
	}
	return config.OOBE, nil
}

// SetOOBEDone 标记 OOBE 已完成
func (a *App) SetOOBEDone() error {
	config, err := a.GetGlobalConfig()
	if err != nil {
		config = &GlobalConfig{}
	}
	config.OOBE = true
	return a.SaveGlobalConfig(config)
}

