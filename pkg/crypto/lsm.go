package crypto

import (
	"context"
	"log"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func (lsm *CryptoBpfLsm) InjectLsmProg(ctx context.Context) error {
	log.Println("Injecting the LSM BPF for crypto validation of bpf progs")

	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err.Error())
	}

	handler, err := utils.ReadEbpfFromSpec(ctx, utils.LSM_CRYPTO_BPF_VERIFER_PROG)
	if err != nil {
		panic(err)
	}

	spec, err := ebpf.NewCollectionWithOptions(handler, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: utils.PINPATH,
		},
	})

	lsm.LsmProgCollection = spec
	if err != nil {
		panic(err.Error())
	}

	prog := spec.Programs[utils.LSM_CRYPTO_VERIFY_PROG]
	if prog == nil {
		panic("program not found")
	}

	link, err := link.AttachLSM(link.LSMOptions{
		Program: prog,
	})

	if err != nil {
		panic(err.Error())
	}

	lsm.Link = link
	lsm.Program = prog

	log.Println("Injected LSM Progs successfully")
	return nil
}

func (lsm *CryptoBpfLsm) RemoveCryptoLSMProgs() error {

	// close the loaded link
	if lsm.Link != nil {
		if err := lsm.Link.Close(); err != nil {
			return err
		}
	}

	// close prog rmeove attach hook
	for _, maps := range lsm.PinnedMaps {
		if lsm.LsmProgCollection != nil {
			if _, fd := lsm.LsmProgCollection.Maps[maps]; fd {
				if lsm.LsmProgCollection.Maps[maps].IsPinned() {
					if err := lsm.LsmProgCollection.Maps[maps].Unpin(); err != nil {
						return err
					}
					lsm.LsmProgCollection.Maps[maps].Close()
				}
			}
		}
	}

	defer func() {
		if lsm.Program != nil {
			lsm.Program.Close()
		}
		if lsm.LsmProgCollection != nil {
			lsm.LsmProgCollection.Close()
		}
	}()
	return nil
}
