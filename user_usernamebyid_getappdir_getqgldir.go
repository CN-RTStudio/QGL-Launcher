package main

import (
	"path/filepath"

)

func (a *App) GetQGLDir() string {
	return filepath.Join(a.GetAppDir(), "QGL")
}
