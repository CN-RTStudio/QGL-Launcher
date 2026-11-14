package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"io"
	"net/http"
	"time"

	"image/png"
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

func httpGetBytes(url string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 皮肤最大 4MB，防止异常响应撑爆内存
}

// extractFacePNG 从 64x64（或 64x32）皮肤图中裁剪脸部并叠加帽子层，输出 64x64 PNG
func extractFacePNG(skinData []byte) ([]byte, error) {
	img, _, err := image.Decode(bytes.NewReader(skinData))
	if err != nil {
		return nil, fmt.Errorf("解码皮肤失败: %w", err)
	}
	bounds := img.Bounds()
	w := bounds.Dx()
	if w < 32 {
		return nil, fmt.Errorf("皮肤图片尺寸不足: %dx%d", w, bounds.Dy())
	}
	scale := w / 64
	if scale < 1 {
		scale = 1
	}
	fx, fy := bounds.Min.X, bounds.Min.Y
	// 按 PCL MySkin.Load 的档案头像合成逻辑：
	// 画布 56x56；脸层 (8,8) 8x8 放大到 48x48 居中（留 4px 边）；
	// 帽子/头发层 (40,8) 8x8 放大到 56x56 铺满叠加（头发包住脸并向外扩一圈）
	// 注意：64x32 旧皮肤也有帽子层（PCL 条件为 宽>=64 且 高>=32）
	const canvas = 56
	out := image.NewNRGBA(image.Rect(0, 0, canvas, canvas))

	// 采样函数：从皮肤图中取某 8x8 区域的像素
	sample := func(regionX, regionY, x, y int) (r, g, b, a uint32) {
		// 目标画布坐标 -> 区域内坐标（区域被放大到 56x56）
		rx := x * 8 / canvas
		ry := y * 8 / canvas
		return img.At(fx+regionX*scale+rx, fy+regionY*scale+ry).RGBA()
	}

	// 1. 脸层 48x48 居中（偏移 4px）：映射回 48x48 坐标再采样
	faceOffset, faceSize := 4, 48
	for y := 0; y < faceSize; y++ {
		for x := 0; x < faceSize; x++ {
			// 48x48 -> 8x8 采样
			rx := x * 8 / faceSize
			ry := y * 8 / faceSize
			out.Set(faceOffset+x, faceOffset+y, img.At(fx+8*scale+rx, fy+8*scale+ry))
		}
	}

	// 2. 帽子层 56x56 铺满，仅叠加不透明像素
	if bounds.Dy() >= 32*scale {
		for y := 0; y < canvas; y++ {
			for x := 0; x < canvas; x++ {
				_, _, _, a := sample(40, 8, x, y)
				if a>>8 > 0 {
					r, g, b, _ := sample(40, 8, x, y)
					out.SetNRGBA(x, y, color.NRGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: uint8(a >> 8)})
				}
			}
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, out); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
