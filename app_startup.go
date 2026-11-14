package main

import (
	"context"
)

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}
