package main

import "strings"

func unquoteYAMLValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}
func flattenYAML(data []byte) (map[string]string, []string) {
	out := map[string]string{}
	dups := []string{}
	type frame struct {
		indent int
		key    string
	}
	stack := []frame{}
	lines := strings.Split(string(data), "\n")
	for _, raw := range lines {
		line := stripYAMLComment(strings.TrimRight(raw, "\r"))
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		body := strings.TrimSpace(line)
		if strings.HasPrefix(body, "- ") || body == "-" {
			continue
		}
		colon := strings.Index(body, ":")
		if colon <= 0 {
			continue
		}
		key := strings.TrimSpace(body[:colon])
		if key == "" {
			continue
		}
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		prefix := make([]string, 0, len(stack)+1)
		for _, f := range stack {
			prefix = append(prefix, f.key)
		}
		prefix = append(prefix, key)
		path := strings.Join(prefix, ".")
		value := unquoteYAMLValue(body[colon+1:])
		if value == "" {
			stack = append(stack, frame{indent: indent, key: key})
			continue
		}
		if _, ok := out[path]; ok {
			dups = append(dups, path)
		}
		out[path] = value
	}
	return out, dups
}
