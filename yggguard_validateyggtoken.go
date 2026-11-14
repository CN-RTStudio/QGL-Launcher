package main

import ()

func validateYggToken(token string, allowEmpty bool) string {
	if token == "" {
		if allowEmpty {
			return ypOK
		}
		return ypTokenBad
	}
	if len(token) > maxYggTokenLen {
		return ypTokenBad
	}
	for _, c := range token {
		if c <= 32 || c == 127 {
			return ypTokenBad
		}
	}
	return ypOK
}

type YggProfile struct {
	Name string // 合法 Minecraft 角色名
	UUID string // 32 位小写十六进制
}

func pickYggProfile(selected *struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}, available []struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}) (YggProfile, bool) {
	try := func(id, name string) (YggProfile, bool) {
		if validateYggProfileName(name) != ypOK {
			return YggProfile{}, false
		}
		uuid, ok := canonicalYggProfileUUID(id)
		if !ok {
			return YggProfile{}, false
		}
		return YggProfile{Name: name, UUID: uuid}, true
	}
	if selected != nil {
		if p, ok := try(selected.ID, selected.Name); ok {
			return p, true
		}
	}
	for i := range available {
		if p, ok := try(available[i].ID, available[i].Name); ok {
			return p, true
		}
	}
	return YggProfile{}, false
}
