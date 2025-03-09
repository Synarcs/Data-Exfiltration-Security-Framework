package rand

import (
	"testing"
)

func TestRandomHasgGenSkb(t *testing.T) {

	t.Run("test Hash", func(t *testing.T) {
		hash := &Hash{}
		hash.GetRandomBootSkbMark()
	})
}
