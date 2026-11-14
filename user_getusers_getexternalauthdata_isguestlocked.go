package main

import (

)

func (a *App) IsGuestLocked() bool {
	currentUser, err := a.GetCurrentUser()
	if err != nil {
		return false
	}
	if currentUser.Type != UserTypeGuest {
		return false
	}
	return !a.guestUnlocked
}

// LockGuest 重新锁定访客用户
