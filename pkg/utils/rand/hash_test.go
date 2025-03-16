package rand

import (
	"log"
	"testing"
)

func TestRandomHasgGenSkb(t *testing.T) {

	t.Run("test Hash", func(t *testing.T) {
		hash := &Hash{}
		hash.GetRandomBootSkbMark()
		log.Println("Generated Big Endian random nounce hash for skb mark clone in kernel", hash.SkbHash)
	})
}
