package main

import (
	"regexp"
	"strings"
)

const (
	adReasonOK              = "ok"
	adReasonMissing         = "missing"
	adReasonUnreadable      = "unreadable"
	adReasonSymlink         = "symlink"
	adReasonTooLarge        = "too-large"
	adReasonWorldWritable   = "world-writable"
	adReasonWorldReadable   = "world-readable"
	adReasonTooManyFiles    = "too-many-files"
	adReasonBadFileName     = "bad-file-name"
	adReasonMalformedJSON   = "malformed-json"
	adReasonDeepNesting     = "deep-nesting"
	adReasonDuplicateKey    = "duplicate-key"
	adReasonLootTraversal   = "loot-traversal"
	adReasonIconTraversal   = "icon-traversal"
	adReasonParentEscape    = "parent-escape"
	adReasonTooManyCriteria = "too-many-criteria"
	adReasonEmptyFile       = "empty-file"

	adMaxFileBytes = 2 << 20
	adMaxFiles     = 128
	adMaxDepth     = 32
	adMaxCriteria  = 64
	adMaxFindings  = 48
)

var adAdvancementDirs = []string{
	"world/advancements",
	"world_nether/advancements",
	"world_the_end/advancements",
}

var adFilePattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\.json$`)

type AdvancementFinding struct {
	Dir      string
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

func adUnsafeResource(value string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	if trimmed == "" {
		return true
	}
	if strings.HasPrefix(trimmed, "/") {
		return true
	}
	if strings.Contains(trimmed, "..") {
		return true
	}
	if strings.ContainsAny(trimmed, "\\\x00") {
		return true
	}
	return false
}
