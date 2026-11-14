package main

import (

)

func (a *App) SetOOBEDone() error {
	config, err := a.GetGlobalConfig()
	if err != nil {
		config = &GlobalConfig{}
	}
	config.OOBE = true
	return a.SaveGlobalConfig(config)
}

