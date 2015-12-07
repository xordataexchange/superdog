package superdog

import (
	"crypto/sha256"
	"fmt"
)

func Sum256String(s string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
}
