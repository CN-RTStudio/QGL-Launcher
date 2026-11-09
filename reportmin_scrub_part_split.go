package main

import "encoding/json"

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
func marshalMinimized(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
