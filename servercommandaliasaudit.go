package main

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
