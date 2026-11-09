package main

const (
	hoReasonOK            = "ok"
	hoReasonMissing       = "missing"
	hoReasonUnreadable    = "unreadable"
	hoReasonSymlink       = "symlink"
	hoReasonTooLarge      = "too-large"
	hoReasonWorldWritable = "world-writable"
	hoReasonWorldReadable = "world-readable"
	hoReasonTooManyTopics = "too-many-topics"
	hoReasonTextTooLong   = "text-too-long"
	hoReasonControlChars  = "control-chars"
	hoReasonRemoteURL     = "remote-url"
	hoReasonWildcardPerm  = "wildcard-permission"
	hoReasonShadowTopic   = "shadowed-topic"
	hoReasonEmptyTopic    = "empty-topic"
	hoReasonDuplicateKey  = "duplicate-key"
	hoReasonUnknownField  = "unknown-field"
	hoReasonBadSection    = "bad-section"

	hoMaxFileBytes = 1 << 20
	hoMaxTopics    = 64
	hoMaxShortText = 256
	hoMaxFullText  = 4096
	hoMaxFindings  = 48
)

var hoConfigCandidates = []string{
	"help.yml",
	"config/help.yml",
}

var hoBuiltinTopics = []string{
	"help",
	"version",
	"plugins",
	"reload",
	"timings",
	"spark",
	"op",
	"deop",
}

var hoKnownSections = []string{
	"general-topics",
	"index-topics",
}
