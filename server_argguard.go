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
