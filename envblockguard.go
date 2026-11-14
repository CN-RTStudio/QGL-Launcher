package main

import (
	"strings"
)

const (
	envNameMaxBytes  = 255   // 环境变量名保守上限
	envValueMaxBytes = 32767 // 单条值的保守上限，给 CreateProcess 0x7FFF 限制留余量
)

type envProblem string

const (
	envProblemNone         envProblem = ""
	envProblemEmptyName    envProblem = "empty-name"
	envProblemNamePadding  envProblem = "name-whitespace-padding"
	envProblemNameEquals   envProblem = "name-contains-equals"
	envProblemNameNUL      envProblem = "name-contains-nul"
	envProblemNameControl  envProblem = "name-contains-control"
	envProblemNameTooLong  envProblem = "name-too-long"
	envProblemValueNUL     envProblem = "value-contains-nul"
	envProblemValueControl envProblem = "value-contains-control"
	envProblemValueTooLong envProblem = "value-too-long"
)

type envRejection struct {
	Name   string
	Reason envProblem
}

func envHasByte(s string, b byte) bool { return strings.IndexByte(s, b) >= 0 }
func envHasNUL(s string) bool          { return envHasByte(s, 0) }
func envHasC0Control(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x1F || c == 0x7F {
			return true
		}
	}
	return false
}
