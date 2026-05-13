package app

import "context"

type Repository interface {
	GetByName(ctx context.Context, name string) (*App, error)
	Create(ctx context.Context, a *App) error
}
