package main

import (
	"strings"
)

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

func inheritedEnvProblem(key, value string) envProblem {
	if len(key) == 0 {
		return envProblemEmptyName
	}
	if envHasNUL(key) {
		return envProblemNameNUL
	}
	if envHasNUL(value) {
		return envProblemValueNUL
	}
	return envProblemNone
}
func acceptExtraEnv(extra map[string]string) (map[string]string, []envRejection) {
	accepted := make(map[string]string, len(extra))
	var rejected []envRejection
	for name, value := range extra {
		if rp := extraEnvNameProblem(name); rp != envProblemNone {
			rejected = append(rejected, envRejection{Name: name, Reason: rp})
			continue
		}
		if rp := extraEnvValueProblem(value); rp != envProblemNone {
			rejected = append(rejected, envRejection{Name: name, Reason: rp})
			continue
		}
		accepted[name] = value
	}
	sortEnvRejections(rejected)
	return accepted, rejected
}
