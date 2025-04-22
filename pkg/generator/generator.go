package generator

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

var ErrEmptyBase = fmt.Errorf("no base provided for random code creation")

const Characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const Numbers = "1234567890"

//TODO: check: code creation safe? collision (same key several times)
// if not safe -> maybe use uuid or ulid

func RandomCode(length int, base ...string) (string, error) {
	if base == nil {
		return "", ErrEmptyBase
	}
	bMerged := strings.Join(base, "")
	randomBytes := make([]byte, length)

	for i := range randomBytes {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(bMerged))))
		if err != nil {
			return "", err
		}

		randomBytes[i] = bMerged[randomIndex.Int64()]
	}
	return string(randomBytes), nil
}
