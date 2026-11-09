package main

var mrpackPackArchiveExts = map[string]bool{".zip": true}

// mrpack 拒绝原因码（空串表示通过）。
const (
	mrpRejectNone          = ""
	mrpRejectEmptyPath     = "empty-path"
	mrpRejectControl       = "control-byte"
	mrpRejectBackslash     = "backslash"
	mrpRejectAbsolute      = "absolute-path"
	mrpRejectDrive         = "drive-prefix"
	mrpRejectBadSegment    = "bad-segment"
	mrpRejectPathTooLong   = "path-too-long"
	mrpRejectPrivateDir    = "private-subroot"
	mrpRejectRootFile      = "root-file"
	mrpRejectRootSensitive = "sensitive-root-file"
	mrpRejectBadExt        = "bad-extension"
	mrpRejectFormat        = "bad-format-version"
	mrpRejectGame          = "bad-game"
	mrpRejectNameControl   = "name-control"
	mrpRejectNameTooLong   = "name-too-long"
	mrpRejectTooManyFiles  = "too-many-files"
	mrpRejectNoHash        = "missing-hash"
	mrpRejectBadHashAlg    = "bad-hash-algorithm"
	mrpRejectBadHashValue  = "bad-hash-value"
	mrpRejectNoDownload    = "missing-download"
	mrpRejectTooManyURLs   = "too-many-downloads"
	mrpRejectURLScheme     = "url-not-https"
	mrpRejectURLUserInfo   = "url-userinfo"
	mrpRejectURLHost       = "url-bad-host"
	mrpRejectURLPrivate    = "url-private-host"
	mrpRejectURLTooLong    = "url-too-long"
	mrpRejectURLDup        = "duplicate-download"
	mrpRejectBadFileSize   = "bad-file-size"
	mrpRejectDepKey        = "bad-dependency-key"
)
