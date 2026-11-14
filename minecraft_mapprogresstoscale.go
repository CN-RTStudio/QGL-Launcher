package main

import (

)

func (a *App) mapProgressToScale(pct float64) float64 {
	if a.progressSpan <= 0 {
		return pct
	}
	mapped := a.progressBase + pct/100*a.progressSpan
	if mapped > 100 {
		mapped = 100
	}
	return mapped
}
