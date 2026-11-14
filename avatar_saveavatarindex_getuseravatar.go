package main

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

)

func (a *App) GetUserAvatar(id string) (string, error) {
	userType := a.GetUserType(id)
	if userType != UserTypePremium && userType != UserTypeExternal {
		return "", nil
	}

	// 读取 UUID 与 session server 地址
	var uuid, sessionURL string
	if userType == UserTypePremium {
		auth, err := a.GetMSAuthData(id)
		if err != nil || auth.UUID == "" {
			return "", nil
		}
		uuid = auth.UUID
		sessionURL = "https://sessionserver.mojang.com/session/minecraft/profile/"
	} else {
		auth, err := a.GetExternalAuthData(id)
		if err != nil || auth.UUID == "" {
			return "", nil
		}
		uuid = auth.UUID
		// ServerURL 形如 https://littleskin.cn/api/yggdrasil，还原为站点根地址
		root := strings.TrimSuffix(strings.TrimSuffix(auth.ServerURL, "/"), "/api/yggdrasil")
		root = strings.TrimSuffix(root, "/authserver")
		sessionURL = root + "/sessionserver/session/minecraft/profile/"
	}
	if uuid == "" {
		return "", nil
	}

	// 1. 查皮肤地址缓存（uuid -> 皮肤 URL）
	idx := a.loadAvatarIndex()
	skinURL := idx.Skins[uuid]
	if skinURL == "" {
		url, err := fetchSkinURL(sessionURL + uuid)
		if err != nil {
			// 未设置自定义皮肤或网络失败：返回空（不缓存失败结果，下次重试）
			fmt.Printf("[Avatar] 获取皮肤地址失败（%s）: %v\n", id, err)
			return "", nil
		}
		if url == "" {
			return "", nil // 用户未设置自定义皮肤
		}
		skinURL = url
		idx.Skins[uuid] = skinURL
		a.saveAvatarIndex(idx)
	}

	// 2. 查脸图缓存（皮肤 URL hash -> png）；.v2 后缀用于 PCL 式合成算法升级后弃用旧缓存
	hash := fmt.Sprintf("%x", sha1.Sum([]byte(skinURL)))
	headPath := filepath.Join(a.avatarCacheDir(), hash+".v2.png")
	if data, err := os.ReadFile(headPath); err == nil && len(data) > 0 {
		return "data:image/png;base64," + base64.StdEncoding.EncodeToString(data), nil
	}

	// 3. 下载皮肤并裁剪脸
	skinData, err := httpGetBytes(skinURL, 15*time.Second)
	if err != nil {
		fmt.Printf("[Avatar] 皮肤下载失败（%s）: %v\n", skinURL, err)
		return "", nil
	}
	facePNG, err := extractFacePNG(skinData)
	if err != nil {
		fmt.Printf("[Avatar] 裁剪头像失败（%s）: %v\n", id, err)
		return "", nil
	}

	// 4. 写缓存并返回
	os.MkdirAll(a.avatarCacheDir(), 0755)
	os.WriteFile(headPath, facePNG, 0644)
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(facePNG), nil
}

// fetchSkinURL 从 session server 获取皮肤 URL，未设置自定义皮肤返回空串
