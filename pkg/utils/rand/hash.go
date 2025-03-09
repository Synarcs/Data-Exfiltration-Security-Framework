package rand

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"log"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
)

// handle all crypto secruity for node agent hash injected in kernel for random hashes
type Hash struct {
	SkbHash   uint32
	Algorithm string
}

func (h *Hash) GetRandomBootSkbMark() {
	var randomNuonceSkbMarkBoot []byte = make([]byte, 24)
	_, err := rand.Read(randomNuonceSkbMarkBoot)
	if err != nil {
		h.SkbHash = utils.DEFAULT_SK_BUFF_NUONCE
	}

	if !utils.DEBUG {
		log.Printf("The eBPF Node Agent uses the current random SKB mark for secure redirection %s",
			hex.EncodeToString(randomNuonceSkbMarkBoot))
	}

	h.SkbHash = binary.LittleEndian.Uint32(randomNuonceSkbMarkBoot)
}
