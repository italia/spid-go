package spidsaml

import (
	"crypto/rand"
	"math/big"
)

func GenerateRandomID() string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, 43)
	for i := 0; i < 43; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return ""
		}
		ret[i] = letters[num.Int64()]
	}

	return "_" + string(ret)
}
