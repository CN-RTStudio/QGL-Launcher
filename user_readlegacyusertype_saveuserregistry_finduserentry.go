package main

import (

)

func (a *App) findUserEntry(id string) *UserEntry {
	entries := a.loadUserRegistry()
	for i := range entries {
		if entries[i].Dir == id {
			return &entries[i]
		}
	}
	return nil
}

// userNameByID 按标识（dir）查显示用户名（查不到返回原值，兼容迁移前调用）
