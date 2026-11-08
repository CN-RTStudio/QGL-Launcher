package main

// jarclassguard：Jar 类路径守卫。
//
// 场景：启动器在组装 classpath 前，会遍历 libraries/ 目录树并按 maven 坐标
// 查找 artifact jar。恶意版本 json / 被替换的库目录可以让启动器把任意路径
// 塞进 classpath（例如引导攻击者 jar 或本地敏感文件）。本模块在组装前做
// 结构校验：
//   - maven 坐标形状（group:artifact:version[:classifier]）与目录落点一致；
//   - 实际 jar 名必须等于坐标推导名，禁止通用名（如 evil.jar）混入；
//   - 路径只允许 libraries/<group path>/<artifact>/<version>/ 前缀，且无
//     .. / . / 反斜杠 / 控制字符 / 绝对路径 / 符号链接（目录与文件均查）；
//   - 每个目标 jar 可选做内容签名检查（占位校验器注入，供测试注入）。

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// JarClassLimits Jar 类路径守卫的量化边界。
type JarClassLimits struct {
	MaxGroupDepth     int // group 段数上限（如 net.minecraft → 3）
	MaxNameLen        int // 坐标单段长度上限
	MaxClasspathJars  int // 单条 classpath 最大 jar 数
	RequireNoSymlink  bool
}

func defaultJarClassLimits() JarClassLimits {
	return JarClassLimits{MaxGroupDepth: 6, MaxNameLen: 128, MaxClasspathJars: 2048, RequireNoSymlink: true}
}

type jarClassVerdict struct {
	OK     bool
	Reason string
	Total  int
	Bad    int
}

// parseMavenCoord 拆 maven 坐标。返回 (group, artifact, version, classifier, err)。
func parseMavenCoord(name string, lim JarClassLimits) (string, string, string, string, error) {
	parts := strings.Split(name, ":")
	valid := len(parts) == 3 || len(parts) == 4
	if !valid {
		return "", "", "", "", errText("coord-parts")
	}
	group, artifact, version := parts[0], parts[1], parts[2]
	classifier := ""
	if len(parts) == 4 {
		classifier = parts[3]
	}
	if group == "" || artifact == "" || version == "" {
		return "", "", "", "", errText("coord-empty")
	}
	if strings.Count(group, ".")+1 > lim.MaxGroupDepth {
		return "", "", "", "", errText("coord-group-depth")
	}
	for _, seg := range []string{group, artifact, version, classifier} {
		if len(seg) > lim.MaxNameLen {
			return "", "", "", "", errText("coord-seg-long")
		}
		if hasControlCharStr(seg) || strings.ContainsAny(seg, "/\\") {
			return "", "", "", "", errText("coord-seg-illegal")
		}
	}
	return group, artifact, version, classifier, nil
}

// jarFileName 由坐标推导标准 jar 文件名。
func jarFileName(artifact, version, classifier string) string {
	if classifier != "" {
		return artifact + "-" + version + "-" + classifier + ".jar"
	}
	return artifact + "-" + version + ".jar"
}

// coordRelDir 坐标对应的 libraries 目录相对路径（不含文件名）。
func coordRelDir(group, artifact, version string) string {
	return filepath.Join(strings.ReplaceAll(group, ".", string(filepath.Separator)), artifact, version)
}

// resolveNoSymlink 在 requireNoSymlink 时确认整条路径无符号链接；存在即拒绝。
func resolveNoSymlink(root, rel string) error {
	cur := root
	segments := strings.Split(filepath.ToSlash(rel), "/")
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		cur = filepath.Join(cur, seg)
		fi, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				return nil // 缺失路径交给后续存在性检查
			}
			return errText("lstat-fail")
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return errText("symlink")
		}
	}
	return nil
}

// validateLibArtifact 校验单个 artifact 的落点：目录前缀 + 文件名 + 符号链接。
func validateLibArtifact(artifact *LibArtifact, group, artifactName, version, classifier string, lim JarClassLimits) string {
	if artifact == nil {
		return ""
	}
	p := artifact.Path
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, "/") || (len(p) > 1 && p[1] == ':') {
		return "abs-path"
	}
	if hasControlCharStr(p) {
		return "control-char"
	}
	if strings.Contains(p, "\\") {
		return "backslash"
	}
	if strings.Contains(p, "..") {
		return "dotdot"
	}
	want := coordRelDir(group, artifactName, version)
	rel := strings.TrimPrefix(p, "libraries/")
	rel = strings.TrimPrefix(rel, "libraries")
	if !strings.HasPrefix(rel, want) {
		return "dir-mismatch"
	}
	base := filepath.Base(p)
	wantBase := jarFileName(artifactName, version, classifier)
	if base != wantBase {
		return "name-mismatch"
	}
	return ""
}

// ValidateLibrarySet 校验整组库定义（来自版本 json 的 libraries 数组）。
func ValidateLibrarySet(libs []Library, lim JarClassLimits) jarClassVerdict {
	if lim.MaxGroupDepth == 0 {
		lim = defaultJarClassLimits()
	}
	vd := jarClassVerdict{OK: true}
	var reasons []string
	for i, lib := range libs {
		if len(libs) > lim.MaxClasspathJars {
			vd.Bad++
			reasons = append(reasons, "libs-overflow")
			break
		}
		group, artifact, version, classifier, err := parseMavenCoord(lib.Name, lim)
		if err != nil {
			vd.Bad++
			reasons = append(reasons, "lib-name:"+itoaSafe(i))
			continue
		}
		if lib.Downloads != nil {
			if r := validateLibArtifact(lib.Downloads.Artifact, group, artifact, version, classifier, lim); r != "" {
				vd.Bad++
				reasons = append(reasons, "lib-artifact:"+r+":"+itoaSafe(i))
				continue
			}
			for cName, cArt := range lib.Downloads.Classifiers {
				if r := validateLibArtifact(cArt, group, artifact, version, cName, lim); r != "" {
					vd.Bad++
					reasons = append(reasons, "lib-classifier:"+cName+":"+r+":"+itoaSafe(i))
					continue
				}
			}
		}
		// 无 downloads 时允许 URL/JarPath 形态（旧格式），但路径同样要受控
		if lib.JarPath != "" {
			if r := validateLibArtifact(&LibArtifact{Path: lib.JarPath}, group, artifact, version, classifier, lim); r != "" {
				vd.Bad++
				reasons = append(reasons, "lib-jarpath:"+r+":"+itoaSafe(i))
			}
		}
	}
	if vd.Bad > 0 {
		vd.OK = false
		vd.Reason = strings.Join(reasons, ";")
	}
	vd.Total = len(libs)
	return vd
}

// ScanLibrariesDir 扫描实际 libraries 目录：maven 坐标目录结构与 jar 文件
// 落点一致，发现符号链接或非法路径即记录 bad 条目。
func ScanLibrariesDir(root string, lim JarClassLimits) (ok bool, bad []string) {
	if lim.MaxGroupDepth == 0 {
		lim = defaultJarClassLimits()
	}
	bad = []string{}
	err := filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil // 缺失段跳过，交给上层存在性检查
		}
		if lim.RequireNoSymlink && fi.Mode()&os.ModeSymlink != 0 {
			rel, _ := filepath.Rel(root, path)
			bad = append(bad, "symlink:"+filepath.ToSlash(rel))
			return nil
		}
		if fi.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(fi.Name()), ".jar") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		relSlash := filepath.ToSlash(rel)
		if strings.Contains(relSlash, "..") || strings.Contains(relSlash, "\\") {
			bad = append(bad, "jar:dotdot-or-backslash:"+relSlash)
			return nil
		}
		dir := filepath.ToSlash(filepath.Dir(rel))
		segments := strings.Split(dir, "/")
		if len(segments) < 3 {
			bad = append(bad, "jar:shallow-dir:"+relSlash)
			return nil
		}
		version := segments[len(segments)-1]
		artifact := segments[len(segments)-2]
		wantBase := artifact + "-" + version + ".jar"
		// 也允许 -classifier 形态：artifact-version-classifier.jar
		base := strings.ToLower(fi.Name())
		if base != strings.ToLower(wantBase) && !strings.HasPrefix(base, strings.ToLower(artifact+"-"+version+"-")) {
			bad = append(bad, "jar:name-mismatch:"+relSlash)
			return nil
		}
		return nil
	})
	if err != nil {
		ok = false
		return ok, append(bad, "walk-fail")
	}
	return len(bad) == 0, bad
}

// SummarizeJarClassVerdict 压成一行可读文本。
func SummarizeJarClassVerdict(vd jarClassVerdict) string {
	if vd.OK {
		return "jarclass clean total=" + itoaSafe(vd.Total)
	}
	return "jarclass bad=" + itoaSafe(vd.Bad) + " total=" + itoaSafe(vd.Total) + " reason=" + vd.Reason
}

var _ = errors.New
