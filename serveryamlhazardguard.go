package main

import ()

const (
	yhReasonOK            = "ok"
	yhReasonSymlink       = "symlink"
	yhReasonTooLarge      = "too-large"
	yhReasonWorldWritable = "world-writable"
	yhReasonUnreadable    = "unreadable"
	yhReasonTooManyFiles  = "file-overflow"
	yhReasonUnsafeTag     = "unsafe-tag"
	yhReasonObjectApply   = "object-apply"
	yhReasonBinaryBlob    = "binary-blob"
	yhReasonAliasBomb     = "alias-bomb"
	yhReasonAliasDepth    = "alias-depth"
	yhReasonTabIndent     = "tab-indent"
	yhReasonDuplicateKey  = "duplicate-key"
	yhReasonMergeKey      = "merge-key"

	yhMaxFiles    = 32
	yhMaxBytes    = 1 << 20
	yhMaxAliases  = 48
	yhMaxDepth    = 8
	yhMaxFindings = 48
)

var yhUnsafeTags = []string{
	"!!javax",
	"!!java.",
	"!!com.sun",
	"!!java.net",
	"!!ruby/object",
	"!!python/object",
	"!!python/name",
	"!<tag:yaml.org,2002:javax",
	"!!org.springframework",
	"!!org.apache",
}

var yhApplyTags = []string{
	"!!python/object/apply",
	"!!python/object/new",
	"!!javax.script.scriptenginemanager",
	"!!java.lang.runtime",
}

func yhInspectFile(a *YamlHazardAudit, root, path string) {
	rel, data, ok := inspectAuditTextFile(a.add, &a.Files, root, path, yhFileCheck)
	if !ok {
		return
	}
	yhScanText(a, rel, string(data))
}
