package rand

import (
	"github.com/google/uuid"
)

func NewUUID() (string, error) {
	id, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
