package main

import (
	"archive/zip"
	"fmt"
)

// scanLog4ShellJar 扫描磁盘上的 jar；只读、不执行、不解压落地。
func scanLog4ShellJar(jarPath string) (*Log4ShellReport, error) {
	zr, err := zip.OpenReader(jarPath)
	if err != nil {
		return nil, fmt.Errorf("打开 jar 失败: %v", err)
	}
	defer zr.Close()
	return scanLog4ShellReader(&zr.Reader), nil
}

func scanLog4ShellReader(zr *zip.Reader) *Log4ShellReport {
	rep := &Log4ShellReport{Findings: []JarFinding{}, findingSeen: map[string]bool{}}
	nestedCount, nestedBytes := 0, 0
	scanLog4ShellInto(rep, zr, 1, "", &nestedCount, &nestedBytes)
	if rep.limitEntries {
		rep.add(JarSeverityInfo, "log4j-scan-limit", "",
			fmt.Sprintf("条目数超过 %d，仅扫描了前 %d 条", log4jMaxEntries, rep.Entries))
	}
	if rep.limitNested {
		rep.add(JarSeverityInfo, "log4j-nested-limit", "",
			fmt.Sprintf("嵌套 jar 深度/数量/体积超限（%d 层 / %d 个），部分未展开",
				log4jNestedDepth, log4jMaxNested))
	}
	return rep
}

// scanLog4ShellInto 扫描单个 zip 层级，prefix 为嵌套 jar 的展示前缀。
