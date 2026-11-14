package main

import (
	"fmt"
)

func (a *MovementGuardAudit) Describe() string {
	return describeFindings(a.Findings, func(f MovementGuardFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func smaLoadText(a *MovementGuardAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func smaBool(props map[string]string, key string) (bool, bool) {
	return propsLookupBool(props, key)
}
