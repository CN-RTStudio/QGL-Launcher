package main

import (
	"os"
)

func (a *App) ReadLicenseFile() string {
	data, err := os.ReadFile("resources/APACHE_LICENSE.txt")
	if err != nil {
		return ""
	}
	return string(data)
}
