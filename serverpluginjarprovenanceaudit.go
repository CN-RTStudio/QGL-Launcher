package main

const (
	pjReasonOK           = "ok"
	pjReasonMissing      = "missing"
	pjReasonEmpty        = "empty-plugins-dir"
	pjReasonUnreadable   = "unreadable"
	pjReasonTooLarge     = "too-large"
	pjReasonTooMany      = "too-many"
	pjReasonSymlink      = "symlink"
	pjReasonBadName      = "bad-name"
	pjReasonNoDescriptor = "missing-plugin-yml"
	pjReasonNoMain       = "missing-main-class"
	pjReasonBadMain      = "bad-main-class"
	pjReasonNestedJar    = "nested-jar"
	pjReasonExecBit      = "executable-bit"
	pjReasonShellClass   = "shell-capable-main"
	pjReasonUnsigned     = "unsigned"
	pjReasonWeakDigest   = "weak-digest"
	pjReasonDuplicateJar = "duplicate-jar"
	pjReasonTooManyFiles = "too-many-entries"

	pjMaxJarBytes    = 64 << 20
	pjMaxJars        = 128
	pjMaxEntries     = 4096
	pjMaxFindings    = 160
	pjMaxMainLen     = 200
	pjMaxNestedDepth = 2
)

var pjSelectedPaths = []string{
	"META-INF/MANIFEST.MF",
	"META-INF/",
	"plugin.yml",
	"paper-plugin.yml",
	"bungee.yml",
	"velocity-plugin.json",
}

var pjShellyMainTokens = []string{
	"runtime.exec",
	"processbuilder",
	"scriptengine",
	"shell",
	"cmd",
	"exec",
}
