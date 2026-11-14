package main

import (

)

func (a *App) findUserByNameAndType(name string, userType UserType) *UserEntry {
	entries := a.loadUserRegistry()
	for i := range entries {
		if entries[i].Name == name && entries[i].Type == userType {
			return &entries[i]
		}
	}
	return nil
}

// SaveExternalAuthData 保存外置登录认证数据（加密存储，和正版账号一样；参数为用户标识 dir）
