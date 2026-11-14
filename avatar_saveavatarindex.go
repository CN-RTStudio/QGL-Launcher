package main

import (
	"encoding/json"
	"os"
	"path/filepath"

)

func (a *App) saveAvatarIndex(idx *avatarIndex) {
	avatarIndexMu.Lock()
	defer avatarIndexMu.Unlock()
	os.MkdirAll(a.avatarCacheDir(), 0755)
	data, err := json.Marshal(idx)
	if err != nil {
		return
	}
	os.WriteFile(filepath.Join(a.avatarCacheDir(), "index.json"), data, 0644)
}

// GetUserAvatar 获取指定用户的头像（皮肤脸），返回 PNG data URL。
// 参数为用户标识 dir（UserInfo.Dir）；仅正版/外置用户有真实皮肤；
// 离线/访客返回空字符串，前端显示首字母。
