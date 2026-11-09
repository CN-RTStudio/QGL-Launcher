package main

import (
	"encoding/json"
)

func minimizeAny(v interface{}, depth int, pol ReportPolicy) (interface{}, bool) {
	if depth > pol.MaxDepth {
		return "<深度超限>", true
	}
	switch t := v.(type) {
	case nil, bool, float64, string:
		return t, false
	case []interface{}:
		var out []interface{}
		trunc := false
		for i, item := range t {
			if i >= pol.MaxArrayItems {
				trunc = true
				break
			}
			m, _ := minimizeAny(item, depth+1, pol)
			out = append(out, m)
		}
		return out, trunc
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		trunc := false
		for k, item := range t {
			if !pol.AllowField(k) {
				trunc = true
				continue
			}
			m, _ := minimizeAny(item, depth+1, pol)
			out[k] = m
		}
		return out, trunc
	default:
		return "<unsupported>", true
	}
}

// marshalMinimized 序列化最小化后的值。标准库 encoding/json 保证输出合法，
// 总预算截断由调用方在字节层处理。
func marshalMinimized(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// MinimizeJSON 把任意 JSON 对象最小化后序列化；返回字节数与丢弃字段数。
// 任何单个字符串值都会过 ScrubTelemetryValue 与 MaxFieldLen。
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
