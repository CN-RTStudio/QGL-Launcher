package main

type DownloadProgress struct {
	TotalBytes      int64   `json:"totalBytes"`
	DownloadedBytes int64   `json:"downloadedBytes"`
	Percentage      float64 `json:"percentage"`
	CurrentFile     string  `json:"currentFile"`
	Status          string  `json:"status"`
}
type DownloadItem struct {
	ID            string  `json:"id"`
	URL           string  `json:"url"`
	CustomName    string  `json:"customName"`
	Type          string  `json:"type"`
	ItemType      string  `json:"itemType"`
	JavaMajor     int     `json:"javaMajor"`
	SavePath      string  `json:"savePath"`
	LoaderName    string  `json:"loaderName"`
	LoaderVersion string  `json:"loaderVersion"`
	OptiFineType  string  `json:"optifineType"`
	OptiFinePatch string  `json:"optifinePatch"`
	Status        string  `json:"status"`
	Progress      float64 `json:"progress"`
	ErrorMsg      string  `json:"errorMsg"`
	// SizeBytes 是该任务“声明”的下载字节数（来自可信镜像/Modrinth files[].size）。
	// 0 表示未知（服务端未给大小），不参与聚合字节预算求和；负数永远不应出现，
	// 预算内核会拒绝。该字段仅用于下载队列的聚合磁盘预算，不改变分发逻辑。
	SizeBytes int64 `json:"sizeBytes"`
}
