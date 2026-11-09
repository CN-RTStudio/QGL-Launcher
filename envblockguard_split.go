package main

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
