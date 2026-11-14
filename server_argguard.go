package main

import (
	"errors"
	"strings"
)

func validateJavaArg(arg string) error {
	if arg == "" {
		return errors.New("空参数")
	}
	if strings.HasPrefix(arg, "@") {
		return errors.New("拒绝 @argfile 参数")
	}
	for _, r := range arg {
		if r == '\r' || r == '\n' || r == 0 {
			return errors.New("参数含控制字符")
		}
	}
	return nil
}

func quoteWindowsArg(arg string) string {
	needQuote := false
	for _, r := range arg {
		if r == ' ' || r == '\t' || r == '"' {
			needQuote = true
			break
		}
	}
	if !needQuote {
		return arg
	}
	var b strings.Builder
	b.WriteByte('"')
	backslashes := 0
	for _, r := range arg {
		switch r {
		case '\\':
			backslashes++
		case '"':
			b.WriteString(strings.Repeat("\\", backslashes*2+1))
			b.WriteByte('"')
			backslashes = 0
		default:
			b.WriteString(strings.Repeat("\\", backslashes))
			backslashes = 0
			b.WriteRune(r)
		}
	}
	b.WriteString(strings.Repeat("\\", backslashes*2))
	b.WriteByte('"')
	return b.String()
}
