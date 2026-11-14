package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

)

func fetchSkinURL(profileURL string) (string, error) {
	body, err := httpGetBytes(profileURL, 8*time.Second)
	if err != nil {
		return "", err
	}
	var profile struct {
		Properties []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(body, &profile); err != nil {
		return "", fmt.Errorf("解析 profile 失败: %w", err)
	}
	var textureValue string
	for _, p := range profile.Properties {
		if p.Name == "textures" {
			textureValue = p.Value
			break
		}
	}
	if textureValue == "" {
		return "", nil // 未设置自定义皮肤（对应 PCL 的"皮肤返回值中不包含皮肤数据项"）
	}
	decoded, err := base64.StdEncoding.DecodeString(textureValue)
	if err != nil {
		return "", fmt.Errorf("解码 textures 失败: %w", err)
	}
	var textures struct {
		Textures struct {
			Skin struct {
				URL string `json:"url"`
			} `json:"skin"`
		} `json:"textures"`
	}
	if err := json.Unmarshal(decoded, &textures); err != nil {
		return "", fmt.Errorf("解析纹理数据失败: %w", err)
	}
	return textures.Textures.Skin.URL, nil
}
