package repository

import (
	"time"

	"auth-service/internal/app"
)

type pgApp struct {
	ID        int64     `gorm:"column:id;primaryKey;autoIncrement"`
	Name      string    `gorm:"column:name;uniqueIndex;not null;type:varchar(100)"`
	ClientID  string    `gorm:"column:client_id;not null;type:text"`
	Provider  string    `gorm:"column:provider;not null;type:varchar(50)"`
	Status    string    `gorm:"column:status;not null;type:varchar(50)"`
	Env       string    `gorm:"column:env;not null;type:varchar(50)"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime"`
}

func (pgApp) TableName() string { return "apps" }

func (p pgApp) toDomain() *app.App {
	return &app.App{
		ID:        p.ID,
		Name:      p.Name,
		ClientID:  p.ClientID,
		Provider:  p.Provider,
		Status:    p.Status,
		Env:       p.Env,
		CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt,
	}
}

func fromDomain(a *app.App) pgApp {
	return pgApp{
		ID:        a.ID,
		Name:      a.Name,
		ClientID:  a.ClientID,
		Provider:  a.Provider,
		Status:    a.Status,
		Env:       a.Env,
		CreatedAt: a.CreatedAt,
		UpdatedAt: a.UpdatedAt,
	}
}
