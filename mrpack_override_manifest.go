package main

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
)

func validateMrpackManifest(m *ModrinthModpackManifest) error {
	if m == nil {
		return mrpackReject(mrpRejectFormat, "清单为空")
	}
	if m.FormatVersion != 1 {
		return mrpackReject(mrpRejectFormat, fmt.Sprintf("formatVersion=%d", m.FormatVersion))
	}
	if strings.ToLower(strings.TrimSpace(m.Game)) != "minecraft" {
		return mrpackReject(mrpRejectGame, "game="+m.Game)
	}
	if m.Name != "" {
		if containsControlByte(m.Name) {
			return mrpackReject(mrpRejectNameControl, "")
		}
		if len(m.Name) > maxMrpackNameLen {
			return mrpackReject(mrpRejectNameTooLong, "")
		}
	}
	if why := validateMrpackDependencies(m.Dependencies); why != mrpRejectNone {
		return mrpackReject(why, "dependencies")
	}
	if len(m.Files) > maxMrpackIndexFiles {
		return mrpackReject(mrpRejectTooManyFiles, fmt.Sprintf("files=%d", len(m.Files)))
	}

	for i := range m.Files {
		f := &m.Files[i]
		rel, why := secureMrpackDestRel(f.Path)
		if why != mrpRejectNone {
			return mrpackReject(why, fmt.Sprintf("files[%d].path=%q", i, f.Path))
		}
		f.Path = rel

		if f.FileSize < 0 || f.FileSize > maxMrpackDeclaredFileSize {
			return mrpackReject(mrpRejectBadFileSize, fmt.Sprintf("files[%d].fileSize=%d", i, f.FileSize))
		}
		if why := validateMrpackHash(f.Hashes); why != mrpRejectNone {
			return mrpackReject(why, fmt.Sprintf("files[%d](%s)", i, rel))
		}
		downloads, why := normalizeMrpackDownloads(f.Downloads)
		if why != mrpRejectNone {
			return mrpackReject(why, fmt.Sprintf("files[%d](%s)", i, rel))
		}
		f.Downloads = downloads

		// env 只允许 client/server 两个键，取值仅限 required/optional/unsupported；
		// 未知键 / 未知取值就地清除（而非拒绝），避免第三方塞自定义键影响客户端选取。
		if f.Env != nil {
			cleaned := make(map[string]string, 2)
			for _, key := range []string{mrpackEnvKeyClient, mrpackEnvKeyServer} {
				if raw, present := f.Env[key]; present {
					if norm := normalizeMrpackEnvSide(raw); norm != "" {
						cleaned[key] = norm
					}
				}
			}
			if len(cleaned) == 0 {
				f.Env = nil
			} else {
				f.Env = cleaned
			}
		}
	}
	return nil
}

func secureMrpackDestRel(raw string) (string, string) {
	clean, why := cleanMrpackPathSegments(raw)
	if why != mrpRejectNone {
		return "", why
	}
	if why := mrpackPathPolicy(clean); why != mrpRejectNone {
		return "", why
	}
	return clean, mrpRejectNone
}
func secureMrpackDest(baseDir, raw string) (string, error) {
	rel, why := secureMrpackDestRel(raw)
	if why != mrpRejectNone {
		return "", fmt.Errorf("%s: %s", describeMrpackReject(why), raw)
	}
	dest := filepath.Join(baseDir, filepath.FromSlash(rel))
	if !PathWithinRoot(dest, baseDir) {
		return "", fmt.Errorf("整合包文件解析后越出实例目录: %s", raw)
	}
	return dest, nil
}

func validateMrpackHash(hashes map[string]string) string {
	if len(hashes) == 0 {
		return mrpRejectNoHash
	}
	for alg, val := range hashes {
		var wantLen int
		switch alg {
		case "sha1":
			wantLen = 40
		case "sha512":
			wantLen = 128
		default:
			return mrpRejectBadHashAlg
		}
		v := strings.TrimSpace(val)
		if len(v) != wantLen {
			return mrpRejectBadHashValue
		}
		if _, err := hex.DecodeString(v); err != nil {
			return mrpRejectBadHashValue
		}
	}
	if _, ok := hashes["sha1"]; !ok {
		if _, ok512 := hashes["sha512"]; !ok512 {
			return mrpRejectNoHash
		}
	}
	return mrpRejectNone
}
