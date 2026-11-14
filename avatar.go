package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

)

// ===== 用户头像（皮肤脸）获取 =====
// 参考 PCL（ModMinecraft.vb McSkinGetAddress / McSkinDownload + MySkin.Load）：
// 1. 通过 session server 的 UUID 接口获取 base64 纹理数据，解析出皮肤 URL
// 2. UUID -> 皮肤 URL 做持久缓存（对应 PCL 的 Cache\Skin\Index*.ini），避免频繁请求被 429 限流
// 3. 皮肤 URL hash -> 脸图文件缓存，URL 不变则直接复用
// 4. 从皮肤图裁剪 8x8 脸部 + 叠加帽子层（40,8），最近邻放大后返回 data URL
// 获取时机与 PCL 一致：前端在登录/选中用户后调用，失败或未设置皮肤则返回空（前端回退首字母）

// avatarIndex 头像地址缓存（QGL/Cache/Avatar/index.json）
type avatarIndex struct {
	Skins map[string]string `json:"skins"` // uuid -> 皮肤 URL
}

var avatarIndexMu sync.Mutex

func (a *App) avatarCacheDir() string {
	return filepath.Join(a.GetQGLDir(), "Cache", "Avatar")
}

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
