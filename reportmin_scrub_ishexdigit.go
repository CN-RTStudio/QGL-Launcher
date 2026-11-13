package main

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isWinDriveStart(s string, i int) bool {
	if i+1 < len(s) && (s[i+1] == ':') && isDriveLetter(s[i]) {
		if i+2 < len(s) && (s[i+2] == '\\' || s[i+2] == '/') {
			return true
		}
	}
	// UNC：\\host\share\…
	return i+1 < len(s) && s[i] == '\\' && s[i+1] == '\\'
}
func isDriveLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
