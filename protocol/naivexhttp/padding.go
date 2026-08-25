package naivexhttp

import "math/rand"

func generatePaddingHeader() string {
	paddingLen := rand.Intn(32) + 30
	padding := make([]byte, paddingLen)
	bits := rand.Uint64()
	for i := range 16 {
		padding[i] = "!#$()+<>?@[]^`{}"[bits&15]
		bits >>= 4
	}
	for i := 16; i < paddingLen; i++ {
		padding[i] = '~'
	}
	return string(padding)
}
