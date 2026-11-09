package main

import "time"

const (
	portProbeFree         = "free"           // 地址可绑定
	portProbeInUse        = "address-in-use" // 地址 / 端口已被占用
	portProbePermission   = "permission-denied"
	portProbeUnreachable  = "unreachable"
	portProbeInvalid      = "invalid-port"
	portProbeNotSupported = "not-supported"
	portProbeUnknown      = "unknown-error"
)

var wildcardProbeAddresses = []string{"0.0.0.0", "::"}

type PortProbeResult struct {
	Address string `json:"address"`
	Free    bool   `json:"free"`
	Reason  string `json:"reason"`
}
type PortAvailability struct {
	Port    int               `json:"port"`
	Free    bool              `json:"free"`
	Reason  string            `json:"reason"`
	Details []PortProbeResult `json:"details"`
}

const probeListenTimeout = 2 * time.Second
