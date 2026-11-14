package main

import (

)

func DefaultGuestPermissions() GuestPermissions {
	return GuestPermissions{
		AllowDownload: true,
		AllowMod:      true,
		AllowEasyQGL:  true,
		AllowSettings: true,
		AllowQGLPlus:  true,
		AllowHelper:   true,
	}
}

// GetGuestPermissions 读取当前用户的访客权限（guest.json，不存在则返回默认全允许）
