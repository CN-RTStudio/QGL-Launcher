package main

import "strings"

func (a *BlueMapAudit) Describe() string {
	return describeFileReason("BlueMap 网页地图配置未发现风险", a.Findings, 12)
}

func sbmLoadText(a *BlueMapAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func sbmParseConf(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if trimmed == "{" || trimmed == "}" || strings.HasSuffix(trimmed, "{") {
			continue
		}
		sep := strings.IndexAny(trimmed, ":=")
		if sep <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(trimmed[:sep]))
		if dot := strings.LastIndex(key, "."); dot >= 0 {
			key = key[dot+1:]
		}
		if space := strings.LastIndex(key, " "); space >= 0 {
			key = key[space+1:]
		}
		value := strings.TrimSpace(trimmed[sep+1:])
		value = strings.TrimSuffix(value, ",")
		value = cfgStripQuotes(value)
		out[key] = value
	}
	return out
}

func sbmBool(props map[string]string, key string) (bool, bool) {
	return propsLookupBool(props, key)
}
