package main

func spmIdentifierKeys(flat map[string]string) []string {
	return spxKeysWithSuffix(flat, []string{
		"metrics-uuid", "metrics_uuid", "server-uuid", "server_uuid",
		"installation-id", "install-id", "instance-id",
	})
}

func spmIPKeys(flat map[string]string) []string {
	return spxKeysWithSuffix(flat, []string{
		"collect-player-ips", "send-player-ips", "log-player-ips",
		"store-ips", "include-ip", "include_ips", "send-ip",
	})
}
