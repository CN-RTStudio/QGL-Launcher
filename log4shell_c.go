package main

type Log4ShellReport struct {
	Entries      int          `json:"entries"`
	ConfigFiles  int          `json:"configFiles"`
	Findings     []JarFinding `json:"findings"`
	findingSeen  map[string]bool
	limitEntries bool
	limitNested  bool
}

func (r *Log4ShellReport) Blocked() bool {
	if r == nil {
		return false
	}
	return anyBlocking(r.Findings, func(f JarFinding) bool { return f.Severity == JarSeverityCritical })
}
