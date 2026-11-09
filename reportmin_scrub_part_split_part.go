package main

func MinimizeJSON(obj map[string]interface{}) ([]byte, int, error) {
	pol := defaultReportPolicy()
	// 字符串值先全局 scrub（map 遍历内做），再递归深度/数组预算。
	scrubbed := make(map[string]interface{}, len(obj))
	var dropped int
	for k, v := range obj {
		if !pol.AllowField(k) {
			dropped++
			continue
		}
		scrubbed[k] = scrubJSONStrings(v, pol.MaxFieldLen)
	}
	minimized, _ := minimizeAny(scrubbed, 0, pol)
	data, err := marshalMinimized(minimized)
	if err != nil {
		return nil, dropped, err
	}
	if len(data) > pol.MaxBytes {
		data = data[:pol.MaxBytes]
	}
	return data, dropped, nil
}

// scrubJSONStrings 递归给 JSON 值里的每个字符串做值级去敏 + 长度上界。
func scrubJSONStrings(v interface{}, maxLen int) interface{} {
	switch t := v.(type) {
	case string:
		out := ScrubTelemetryValue(t)
		if len(out) > maxLen {
			out = out[:maxLen-3] + "..."
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, item := range t {
			out[i] = scrubJSONStrings(item, maxLen)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, item := range t {
			out[k] = scrubJSONStrings(item, maxLen)
		}
		return out
	default:
		return v
	}
}
