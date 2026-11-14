package main

import (
	"fmt"
	"strings"
)

func (a *CommandBlockAudit) Describe() string {
	return describeFindings(a.Findings, func(f CommandBlockFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func scbLoadText(a *CommandBlockAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func scbPropBool(props map[string]string, key string) (bool, bool) {
	return propsLookupBool(props, key)
}

func scbPropInt(props map[string]string, key string) (int, bool) {
	value, ok := props[strings.ToLower(key)]
	if !ok {
		return 0, false
	}
	return cfgParseInt(value)
}
