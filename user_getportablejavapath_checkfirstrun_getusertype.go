package main

import (

)

func (a *App) GetUserType(id string) UserType {
	if entry := a.findUserEntry(id); entry != nil {
		return entry.Type
	}
	return a.readLegacyUserType(a.userDirFor(id))
}

// saveUserType 保存用户类型（参数为用户标识 dir，同步更新注册表）
