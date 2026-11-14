package main

const (
	maxGameArgValueBytes = 32 * 1024
	maxExternalGameArgs  = 512
)

var hijackGameArgFlags = map[string]struct{}{
	"server":                {},
	"port":                  {},
	"quickplaymultiplayer":  {},
	"quickplaysingleplayer": {},
	"quickplayrealms":       {},
	"proxyhost":             {},
	"proxyport":             {},
	"proxyuser":             {},
	"proxypass":             {},
	"proxypass_":            {},
	"initialdir":            {}, // 等价于改 gameDir 的第三方 client 约定
}

type GameArgAudit struct {
	Findings []LaunchFinding `json:"findings"`
	Critical int             `json:"critical"`
	Warns    int             `json:"warns"`
	// SafeExternal 仅保留来自外部段、且通过全部检查的参数（保持顺序）。
	SafeExternal []string `json:"safeExternal"`
	Rejected     int      `json:"rejected"`
}

func (g *GameArgAudit) add(code, severity, field, detail string) {
	g.Findings = append(g.Findings, LaunchFinding{Code: code, Severity: severity, Field: field, Detail: detail})
	switch severity {
	case launchSeverityCritical:
		g.Critical++
	case launchSeverityWarn:
		g.Warns++
	}
}

func (g *GameArgAudit) HasCritical() bool { return g.Critical > 0 }

// FirstCriticalCode 返回首个 critical 代码。
