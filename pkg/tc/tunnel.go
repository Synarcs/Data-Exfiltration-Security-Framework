package tc

import (
	"log"

	"github.com/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
)

func PollNetlinkKernelHandlerMap() {

}

func AttachNetlinkSockHandler() error {
	log.Println("Attaching the Netlink Tunnel Tap Socket Handler Scanner")
	handler, err := ebpf.LoadCollectionSpec(utils.SOCK_TUNNEL_CODE_EBPF)

	if err != nil {
		log.Fatal("error loading the xdp program over interface")
		return err
	}

	spec, err := ebpf.NewCollection(handler)
	if err != nil {
		log.Fatal("error loading the xdp program over interface")
		return err
	}

	defer spec.Close()
	prog := spec.Programs[utils.SOCK_TUNNEL_CODE]
	defer prog.Close()

	for _, name := range spec.Maps {
		log.Println("maps used are ", name.String())
	}

	log.Println("Done attaching the Netlink Tunnel Tap Socket Handler Scanner")
	return nil
}

func DetachSockHandler() error {
	return nil
}
