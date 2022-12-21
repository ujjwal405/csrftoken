package randomstring

import (
	"crypto/rand"
	"encoding/base64"
)

func generaterandombyte(value int) ([]byte, error) {
	b := make([]byte, value)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil

}
func Generaterandomstring(val int) (string, error) {
	b, err := generaterandombyte(val)
	return base64.URLEncoding.EncodeToString(b), err
}
