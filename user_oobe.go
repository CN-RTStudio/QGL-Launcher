package main

func (a *App) GetOOBEDone() (bool, error) {
	config, err := a.GetGlobalConfig()
	if err != nil {
		return false, err
	}
	return config.OOBE, nil
}

func (a *App) SetOOBEDone() error {
	config, err := a.GetGlobalConfig()
	if err != nil {
		config = &GlobalConfig{}
	}
	config.OOBE = true
	return a.SaveGlobalConfig(config)
}

func (a *App) GetUserOOBEDone() (bool, error) {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return false, err
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		return false, err
	}
	return config.OOBE, nil
}

func (a *App) SetUserOOBEDone() error {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return err
	}
	config, err := a.GetUserConfig(currentUser.Username)
	if err != nil {
		config = &UserConfig{}
	}
	config.OOBE = true
	return a.SaveUserConfig(currentUser.Username, config)
}
