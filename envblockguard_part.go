package main

import "strings"

func extraEnvNameProblem(name string) envProblem {
	if len(name) == 0 {
		return envProblemEmptyName
	}
	if strings.TrimSpace(name) != name {
		return envProblemNamePadding
	}
	if envHasByte(name, '=') {
		return envProblemNameEquals
	}
	if envHasNUL(name) {
		return envProblemNameNUL
	}
	if envHasC0Control(name) {
		return envProblemNameControl
	}
	if len(name) > envNameMaxBytes {
		return envProblemNameTooLong
	}
	return envProblemNone
}

// extraEnvValueProblem 校验 extra 值：拒绝 NUL、其它 C0/DEL 控制字符与超长值。
func extraEnvValueProblem(value string) envProblem {
	if envHasNUL(value) {
		return envProblemValueNUL
	}
	if envHasC0Control(value) {
		return envProblemValueControl
	}
	if len(value) > envValueMaxBytes {
		return envProblemValueTooLong
	}
	return envProblemNone
}
