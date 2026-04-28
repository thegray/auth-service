package rest

import "time"

type pasetoKeysResponse struct {
	Keys []pasetoKey `json:"keys"`
}

type pasetoKey struct {
	KID string    `json:"kid"`
	Pub string    `json:"pub"`
	IAT time.Time `json:"iat"`
}
