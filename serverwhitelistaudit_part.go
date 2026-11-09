package main

func wlUUIDVersion(value string) int {
	if len(value) < 15 {
		return 0
	}
	ch := value[14]
	if ch >= '0' && ch <= '9' {
		return int(ch - '0')
	}
	if ch >= 'a' && ch <= 'f' {
		return int(ch-'a') + 10
	}
	return 0
}
func wlNameValid(name string) bool {
	if name == "" || len(name) > 16 {
		return false
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if ch < 0x21 || ch == 0x7f {
			return false
		}
		switch ch {
		case '"', '\'', '\\', '/', ';', '&', '|', '$', '<', '>':
			return false
		}
	}
	return true
}

type wlEntry struct {
	UUID                string `json:"uuid"`
	Name                string `json:"name"`
	Level               int    `json:"level"`
	BypassesPlayerLimit bool   `json:"bypassesPlayerLimit"`
}
