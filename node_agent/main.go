package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	tc "github.com/Data-Exfiltration-Security-Framework/pkg/tc"
	xdp "github.com/Data-Exfiltration-Security-Framework/pkg/xdp"
	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

func tcHandler() {

	tcHandler := tc.TCHandler{}
	ctx := context.Background()
	spec, err := tcHandler.ReadEbpfFromSpec(&ctx)

	if err != nil {
		panic(err.Error())
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(err.Error())
	}

	defer collection.Close()

	if len(collection.Programs) > 0 {
		fmt.Println("Multiple programs found in the root collection")
	}
	prog := collection.Programs["classify"]
	if prog == nil {
		panic(fmt.Errorf("No Cliassify TC Egress collection found").Error())
	}

	tcHandler.AttachTcHandler(&ctx, prog)
}

func main() {
	mkae := tc.NodeTcHandler([3]int{-1, -2, -3})
	var tst chan os.Signal = make(chan os.Signal)

	// if err := xdp.LinkXdp(func(interfaceId *int) error { return nil }); err != nil {

	// }
	if err := xdp.LinkXdp(func(interfaceId *int) error { return nil })(1 << 10); err != nil {
		panic(err.Error())
	}

	signal.Notify(tst, syscall.SIGKILL, syscall.SIGINT)

	var ctx context.Context
	mux := http.NewServeMux()
	info := &http.Server{
		Addr:    ":3000",
		Handler: mux,
		BaseContext: func(l net.Listener) context.Context {
			ctx = context.WithValue(context.Background(), ":3000", l.Addr().String())
			return ctx
		},
	}
	fmt.Println("Server listen on port :: ", info.Addr)

	links, err := netlink.LinkList()
	if err != nil {
		panic(err.Error())
	}

	for _, link := range links {
		fmt.Println(link.Attrs().MTU, link.Attrs().Name)
	}

	_, ok := <-tst

	if ok {
		fmt.Println("channel is closed", os.Getpid())
		return
	}
	fmt.Println(mkae)
}
