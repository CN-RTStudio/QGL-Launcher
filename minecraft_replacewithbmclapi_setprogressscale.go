package main

import (

)

func (a *App) setProgressScale(base, span float64) {
	a.progressBase = base
	a.progressSpan = span
}

// mapProgressToScale 将子进度映射到当前阶段区间
