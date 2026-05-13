package app

import "time"

type App struct {
	ID        int64
	Name      string
	ClientID  string
	Provider  string
	Status    string
	Env       string
	CreatedAt time.Time
	UpdatedAt time.Time
}
