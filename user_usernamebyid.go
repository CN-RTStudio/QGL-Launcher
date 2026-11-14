package main

import (

)

func (a *App) userNameByID(id string) string {
	if entry := a.findUserEntry(id); entry != nil {
		return entry.Name
	}
	return id
}

// userDirFor 用户文件夹路径（标识 = 随机文件夹名）
