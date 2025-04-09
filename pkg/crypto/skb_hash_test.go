package crypto

import (
	"testing"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
)

func TestRandomHasgGenSkb(t *testing.T) {

	t.Run("test Hash", func(t *testing.T) {
		hash := &Hash{}
		hash.GetRandomBootSkbMark()
		utils.Log("Generated Big Endian random nounce hash for skb mark clone in kernel", hash.SkbHash)
	})
}
