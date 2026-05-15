package rest

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type PasetoKeysHandler struct {
	publicKeyBase64 string
	keyIssuedAt     time.Time
	keys            []pasetoKey
}

func NewPasetoKeysHandler(publicKeyBase64 string, keyIssuedAt time.Time, kids []string) *PasetoKeysHandler {
	seen := map[string]struct{}{}
	keys := make([]pasetoKey, 0, len(kids))
	for _, kid := range kids {
		if kid == "" {
			continue
		}
		if _, ok := seen[kid]; ok {
			continue
		}
		seen[kid] = struct{}{}
		keys = append(keys, pasetoKey{
			KID: kid,
			Pub: publicKeyBase64,
			IAT: keyIssuedAt.UTC(),
		})
	}

	return &PasetoKeysHandler{
		publicKeyBase64: publicKeyBase64,
		keyIssuedAt:     keyIssuedAt.UTC(),
		keys:            keys,
	}
}

func (h *PasetoKeysHandler) Get(c *gin.Context) {
	if h == nil || h.publicKeyBase64 == "" {
		c.JSON(http.StatusOK, pasetoKeysResponse{Keys: []pasetoKey{}})
		return
	}
	c.JSON(http.StatusOK, pasetoKeysResponse{Keys: h.keys})
}
