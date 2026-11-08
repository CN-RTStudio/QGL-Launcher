package main

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

const (
	pingPayloadMaxBytes     = 64 << 10
	pingVersionMaxRunes     = 64
	pingMotdMaxRunes        = 300
	pingPlayerCountLimit    = 1000000
	pingLatencyLimitMS      = 60000
	pingDescriptionMaxDepth = 8
	pingDescriptionMaxNodes = 256
)

const (
	pingReasonOK         = "ok"
	pingReasonEmpty      = "empty"
	pingReasonTooLarge   = "too_large"
	pingReasonBadJSON    = "bad_json"
	pingReasonBadShape   = "bad_shape"
	pingReasonNoVersion  = "no_version"
	pingReasonBadPlayers = "bad_players"
	pingReasonBadLatency = "bad_latency"
)

type ServerPingAudit struct {
	Version         string
	Protocol        int
	Online          int
	Max             int
	Motd            string
	FaviconAccepted bool
	LatencyMS       int
	Warnings        []string
	Reason          string
}

func pingFlattenDescription(value interface{}, depth int, nodes *int) string {
	if value == nil || depth > pingDescriptionMaxDepth {
		return ""
	}
	*nodes++
	if *nodes > pingDescriptionMaxNodes {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case []interface{}:
		var sb strings.Builder
		for _, item := range v {
			sb.WriteString(pingFlattenDescription(item, depth+1, nodes))
		}
		return sb.String()
	case map[string]interface{}:
		var sb strings.Builder
		if text, ok := v["text"].(string); ok {
			sb.WriteString(text)
		}
		if extra, ok := v["extra"]; ok {
			sb.WriteString(pingFlattenDescription(extra, depth+1, nodes))
		}
		return sb.String()
	default:
		return ""
	}
}

func pingIntField(v interface{}, limit int) (int, bool) {
	f, ok := v.(float64)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	if f < 0 {
		return 0, false
	}
	if f > float64(limit) {
		return limit, true
	}
	if f != math.Trunc(f) {
		return 0, false
	}
	return int(f), true
}

func DescribeServerPingAudit(a ServerPingAudit) string {
	return fmt.Sprintf("reason=%s version=%s online=%d max=%d latency=%d warnings=%d",
		a.Reason, a.Version, a.Online, a.Max, a.LatencyMS, len(a.Warnings))
}

func AuditServerPingPayload(raw []byte, latencyMS int) ServerPingAudit {
	result := ServerPingAudit{Reason: pingReasonOK, LatencyMS: latencyMS}
	if latencyMS < 0 || latencyMS > pingLatencyLimitMS {
		result.Warnings = append(result.Warnings, "ping latency outside the expected window")
		if latencyMS < 0 {
			result.LatencyMS = 0
		} else {
			result.LatencyMS = pingLatencyLimitMS
		}
	}
	if len(raw) == 0 {
		result.Reason = pingReasonEmpty
		return result
	}
	if len(raw) > pingPayloadMaxBytes {
		result.Reason = pingReasonTooLarge
		return result
	}
	var payload interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		result.Reason = pingReasonBadJSON
		return result
	}
	obj, ok := payload.(map[string]interface{})
	if !ok {
		result.Reason = pingReasonBadShape
		return result
	}
	versionObj, _ := obj["version"].(map[string]interface{})
	versionName, _ := versionObj["name"].(string)
	versionName = strings.TrimSpace(ServerTextForDisplay(versionName, pingVersionMaxRunes))
	if versionName == "" {
		result.Reason = pingReasonNoVersion
		return result
	}
	result.Version = versionName
	if proto, ok := pingIntField(versionObj["protocol"], pingPlayerCountLimit); ok {
		result.Protocol = proto
	}
	playersObj, hasPlayers := obj["players"].(map[string]interface{})
	if !hasPlayers {
		result.Reason = pingReasonBadPlayers
		return result
	}
	online, okOnline := pingIntField(playersObj["online"], pingPlayerCountLimit)
	maxPlayers, okMax := pingIntField(playersObj["max"], pingPlayerCountLimit)
	if !okOnline || !okMax {
		result.Reason = pingReasonBadPlayers
		return result
	}
	result.Online = online
	result.Max = maxPlayers
	if online > maxPlayers {
		result.Warnings = append(result.Warnings, "online player count exceeds the reported maximum")
	}
	if description, exists := obj["description"]; exists {
		nodes := 0
		result.Motd = ServerTextForDisplay(pingFlattenDescription(description, 0, &nodes), pingMotdMaxRunes)
	}
	if favicon, exists := obj["favicon"].(string); exists && strings.TrimSpace(favicon) != "" {
		if _, err := ValidateServerFavicon(favicon); err != nil {
			result.Warnings = append(result.Warnings, "favicon rejected: "+err.Error())
		} else {
			result.FaviconAccepted = true
		}
	}
	if protocol, exists := versionObj["protocol"]; exists {
		if _, ok := pingIntField(protocol, pingPlayerCountLimit); !ok {
			result.Warnings = append(result.Warnings, "protocol field is not a bounded integer")
		}
	}
	return result
}

func (a *App) AuditServerPing(raw string, latencyMS int) ServerPingAudit {
	audit := AuditServerPingPayload([]byte(raw), latencyMS)
	if audit.Reason != pingReasonOK {
		recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
			"serverping", "服务器 ping 响应未通过校验: "+DescribeServerPingAudit(audit))
	} else if len(audit.Warnings) > 0 {
		recordSecurityEvent(auditCategoryExternalURL, auditSeverityInfo, auditActionDetected,
			"serverping", "服务器 ping 响应存在可疑字段: "+DescribeServerPingAudit(audit))
	}
	return audit
}
