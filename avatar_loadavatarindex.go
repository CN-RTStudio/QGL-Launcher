package main

import (
	"encoding/json"
	"os"
	"path/filepath"

)

func (a *App) loadAvatarIndex() *avatarIndex {
	avatarIndexMu.Lock()
	defer avatarIndexMu.Unlock()
	idx := &avatarIndex{Skins: map[string]string{}}
	data, err := os.ReadFile(filepath.Join(a.avatarCacheDir(), "index.json"))
	if err == nil {
		json.Unmarshal(data, idx)
	}
	if idx.Skins == nil {
		idx.Skins = map[string]string{}
	}
	return idx
}
