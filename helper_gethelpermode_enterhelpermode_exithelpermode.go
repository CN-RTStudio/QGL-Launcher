package main

import (
)

func (a *App) ExitHelperMode() error {
	config, err := a.GetGlobalConfig()
	if err != nil {
		return err
	}
	config.HelperMode = false
	config.HelperModeDir = ""
	return a.SaveGlobalConfig(config)
}
