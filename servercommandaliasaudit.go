package main

import ()

const (
	caReasonOK             = "ok"
	caReasonMissing        = "missing"
	caReasonUnreadable     = "unreadable"
	caReasonSymlink        = "symlink"
	caReasonTooLarge       = "too-large"
	caReasonWorldWritable  = "world-writable"
	caReasonWorldReadable  = "world-readable"
	caReasonCatchAll       = "catch-all-alias"
	caReasonShadowed       = "shadowed-command"
	caReasonInternalTarget = "internal-target"
	caReasonTooManyAlias   = "too-many-aliases"
	caReasonBadName        = "bad-alias-name"
	caReasonDuplicate      = "duplicate-alias"
	caReasonVariableTarget = "variable-target"
	caReasonEmptyTarget    = "empty-target"
	caReasonBadIndent      = "bad-indent"
	caReasonUnknownSection = "unknown-section"

	caMaxFileBytes = 1 << 20
	caMaxAliases   = 64
	caMaxTargets   = 8
	caMaxFindings  = 48
)

var caConfigCandidates = []string{
	"commands.yml",
	"config/commands.yml",
}

var caPrivilegedCommands = []string{
	"op",
	"deop",
	"stop",
	"restart",
	"ban",
	"ban-ip",
	"pardon",
	"pardon-ip",
	"whitelist",
	"kick",
	"save-off",
	"save-all",
	"reload",
	"plugins",
	"permissions",
}

func caCheckFile(audit *CommandAliasAudit, rel string) bool {
	return checkServerCfgFile(audit.Dir, rel, caMaxFileBytes,
		cfgFileReasons{
			Missing:       caReasonMissing,
			Unreadable:    caReasonUnreadable,
			Symlink:       caReasonSymlink,
			TooLarge:      caReasonTooLarge,
			WorldWritable: caReasonWorldWritable,
			WorldReadable: caReasonWorldReadable,
		},
		cfgFileLabels{Noun: "配置文件", SizeLabel: "配置体积"},
		func(reason, detail string, blocking bool) { audit.add(rel, "", reason, detail, blocking) })
}
func caStripComment(line string) string {
	inSingle := false
	inDouble := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble && i > 0 && (line[i-1] == ' ' || line[i-1] == '\t') {
				return line[:i]
			}
		}
	}
	return line
}
