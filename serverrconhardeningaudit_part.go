package main

func (a *RconHardeningAudit) Describe() string {
	return describeAuditFindings("RCON 配置未发现风险", a.Findings, 10,
		func(f RconHardeningFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f RconHardeningFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func syrPasswordVariety(password string) int {
	classes := 0
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSymbol := false
	for _, r := range password {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	if hasLower {
		classes++
	}
	if hasUpper {
		classes++
	}
	if hasDigit {
		classes++
	}
	if hasSymbol {
		classes++
	}
	return classes
}
