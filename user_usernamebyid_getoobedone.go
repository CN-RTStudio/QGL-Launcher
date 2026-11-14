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
