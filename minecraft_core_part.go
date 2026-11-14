package main

type VersionJSON struct {
	ID            string            `json:"id"`
	Type          string            `json:"type"`
	MainClass     string            `json:"mainClass"`
	MinecraftArgs string            `json:"minecraftArguments"`
	Arguments     *ArgumentsObj     `json:"arguments"`
	Libraries     []Library         `json:"libraries"`
	Downloads     *VersionDownloads `json:"downloads"`
	AssetIndex    *AssetIndexRef    `json:"assetIndex"`
	ReleaseTime   string            `json:"releaseTime"`
	InheritsFrom  string            `json:"inheritsFrom"`
	Jar           string            `json:"jar"`
}

type ArgumentsObj struct {
	JVM  []interface{} `json:"jvm"`
	Game []interface{} `json:"game"`
}

type Library struct {
	Name      string            `json:"name"`
	Downloads *LibDownloads     `json:"downloads"`
	Natives   map[string]string `json:"natives"`
	Rules     []Rule            `json:"rules"`
	URL       string            `json:"url"`
	JarPath   string            `json:"path"`
}

type LibDownloads struct {
	Artifact    *LibArtifact            `json:"artifact"`
	Classifiers map[string]*LibArtifact `json:"classifiers"`
}

type LibArtifact struct {
	Path string `json:"path"`
	URL  string `json:"url"`
	SHA1 string `json:"sha1"`
	Size int64  `json:"size"`
}

type Rule struct {
	Action   string          `json:"action"`
	OS       *RuleOS         `json:"os"`
	Features map[string]bool `json:"features"`
}

type RuleOS struct {
	Name    string `json:"name"`
	Arch    string `json:"arch"`
	Version string `json:"version"`
}

type VersionDownloads struct {
	Client *LibArtifact `json:"client"`
	Server *LibArtifact `json:"server"`
}

type AssetIndexRef struct {
	ID        string `json:"id"`
	URL       string `json:"url"`
	SHA1      string `json:"sha1"`
	Size      int64  `json:"size"`
	TotalSize int64  `json:"totalSize"`
}

type AssetIndex struct {
	Objects map[string]AssetObject `json:"objects"`
}

type AssetObject struct {
	Hash string `json:"hash"`
	Size int64  `json:"size"`
}

// InstalledVersionInfo 安装版本的信息
type InstalledVersionInfo struct {
	FolderName string `json:"folderName"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	Loader     string `json:"loader"`
	Type       string `json:"type"`
}
