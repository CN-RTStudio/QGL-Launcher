package main

import (
	"errors"
	"fmt"
)

const (
	privateStoreMaxBytes int64 = 1 << 20
	maxStoredPathLen           = 32768
)

func readPrivateStoreJSON(path string, out any, label string) error {
	return readLocalJSONBounded(path, out, privateStoreMaxBytes, label)
}

func readPrivateStoreBytes(path string, label string) ([]byte, error) {
	body, err := readBoundedFile(path, privateStoreMaxBytes)
	if err != nil {
		if errors.Is(err, errLocalFileTooLarge) {
			recordSecurityEvent("local-json", auditSeverityCritical, auditActionBlocked,
				"userstore", fmt.Sprintf("%s实际体积超过上限 %d: %s", label, privateStoreMaxBytes, path))
		}
		return nil, err
	}
	return body, nil
}

func readPasswordData(path string) (PasswordData, error) {
	var pwd PasswordData
	if err := readPrivateStoreJSON(path, &pwd, "密码文件"); err != nil {
		return PasswordData{}, err
	}
	return pwd, nil
}
