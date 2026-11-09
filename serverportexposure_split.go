package main

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func AuditServerPortExposure(serverDir string) (PortExposureAudit, error) {
	audit := PortExposureAudit{Path: filepath.Join(serverDir, "server.properties"), Ports: map[string]int{}}
	info, err := os.Lstat(audit.Path)
	if os.IsNotExist(err) {
		audit.Findings = append(audit.Findings, PortFinding{
			Key: "server.properties", Reason: portReasonMissingFile,
			Detail: "缺少配置文件，无法确认监听端口", Blocking: false,
		})
		return audit, nil
	}
	if err != nil {
		return audit, err
	}
	audit.Present = true
	if info.Mode()&os.ModeSymlink != 0 {
		audit.Findings = append(audit.Findings, PortFinding{
			Key: "server.properties", Reason: portReasonSymlink,
			Detail: "配置文件是符号链接", Blocking: true,
		})
		return audit, nil
	}
	if !info.Mode().IsRegular() {
		audit.Findings = append(audit.Findings, PortFinding{
			Key: "server.properties", Reason: portReasonNotRegular,
			Detail: "配置文件不是普通文件", Blocking: true,
		})
		return audit, nil
	}
	if info.Size() > portMaxPropertiesBytes {
		audit.Findings = append(audit.Findings, PortFinding{
			Key: "server.properties", Reason: portReasonTooLarge,
			Detail: "配置文件超过 1 MiB", Blocking: true,
		})
		return audit, nil
	}
	data, err := readBoundedFile(audit.Path, auditTextReadMaxBytes)
	if err != nil {
		return audit, err
	}
	props := parseServerProperties(data)

	rconEnabled := propTruthy(props, "enable-rcon")
	queryEnabled := propTruthy(props, "enable-query")

	serverPort := defaultServerPort
	if raw, ok := props.Get("server-port"); ok {
		value, finding := parsePortValue("server-port", raw)
		if finding != nil {
			audit.Findings = append(audit.Findings, *finding)
		} else {
			serverPort = value
		}
	}
	audit.Ports["server-port"] = serverPort

	queryPort := serverPort
	if raw, ok := props.Get("query.port"); ok {
		value, finding := parsePortValue("query.port", raw)
		if finding != nil {
			audit.Findings = append(audit.Findings, *finding)
			if queryEnabled {
				audit.Findings[len(audit.Findings)-1].Blocking = true
			}
		} else {
			queryPort = value
		}
	}
	if queryEnabled {
		audit.Ports["query.port"] = queryPort
	}

	rconPort := defaultRconPort
	if raw, ok := props.Get("rcon.port"); ok {
		value, finding := parsePortValue("rcon.port", raw)
		if finding != nil {
			audit.Findings = append(audit.Findings, *finding)
		} else {
			rconPort = value
		}
	}
	if rconEnabled {
		audit.Ports["rcon.port"] = rconPort
	}

	if raw, ok := props.Get("management-server-port"); ok {
		if value, finding := parsePortValue("management-server-port", raw); finding != nil {
			audit.Findings = append(audit.Findings, *finding)
		} else if value != defaultManagementPort {
			audit.Ports["management-server-port"] = value
			if value < 1024 {
				audit.Findings = append(audit.Findings, PortFinding{
					Key: "management-server-port", Value: strconv.Itoa(value), Reason: portReasonPrivileged,
					Detail: "管理端口落在特权端口区间", Blocking: false,
				})
			}
		}
	}

	if !rconEnabled {
		if raw, ok := props.Get("rcon.port"); ok && strings.TrimSpace(raw) != "" {
			if value, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && value > 0 && value != defaultRconPort {
				audit.Findings = append(audit.Findings, PortFinding{
					Key: "rcon.port", Value: raw, Reason: portReasonDisabledPort,
					Detail: "RCON 未启用但配置了非默认端口", Blocking: false,
				})
			}
		}
	}
	if !queryEnabled {
		if raw, ok := props.Get("query.port"); ok {
			if value, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && value > 0 && value != serverPort {
				audit.Findings = append(audit.Findings, PortFinding{
					Key: "query.port", Value: raw, Reason: portReasonDisabledPort,
					Detail: "query 未启用但配置了独立端口", Blocking: false,
				})
			}
		}
	}

	owners := map[int][]string{}
	for key, value := range audit.Ports {
		owners[value] = append(owners[value], key)
	}
	keys := make([]int, 0, len(owners))
	for port := range owners {
		keys = append(keys, port)
	}
	sort.Ints(keys)
	for _, port := range keys {
		names := owners[port]
		if len(names) < 2 {
			continue
		}
		sort.Strings(names)
		audit.Findings = append(audit.Findings, PortFinding{
			Key: strings.Join(names, "+"), Value: strconv.Itoa(port), Reason: portReasonConflict,
			Detail: "多个服务监听同一端口，启用时会互相抢占", Blocking: true,
		})
	}
	for _, key := range []string{"server-port", "query.port", "rcon.port"} {
		value, ok := audit.Ports[key]
		if !ok || value >= 1024 {
			continue
		}
		audit.Findings = append(audit.Findings, PortFinding{
			Key: key, Value: strconv.Itoa(value), Reason: portReasonPrivileged,
			Detail: "服务端口落在特权端口区间", Blocking: false,
		})
	}
	return audit, nil
}

func propTruthy(props *serverProperties, key string) bool {
	raw, ok := props.Get(key)
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}
