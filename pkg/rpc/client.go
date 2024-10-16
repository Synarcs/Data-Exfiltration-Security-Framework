package rpc

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	pb "github.com/Data-Exfiltration-Security-Framework/pkg/rpc/pb"
	"github.com/Data-Exfiltration-Security-Framework/pkg/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// the stream client is control my node agent to receive server side streams from server
// the kernel will detach and remove fd for the socket once the parent process is killed of the node agent
func exfil_client() {
	clientId := flag.Int("id", 0, "the client id to use for streaming")
	flag.Parse()
	fmt.Println("connected with client id ", *clientId)
	conn, err := grpc.NewClient(":3200", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err.Error())
	}
	defer conn.Close()

	client := pb.NewNodeAgentServiceClient(conn)
	val, err := client.GetExfilDomains(context.Background(), &pb.ExfilDomains{
		Tld:         "com",
		Domain:      "google.com",
		TotalLength: 10,
	})
	if err != nil {
		log.Println(err)
	}

	var reader chan os.Signal = make(chan os.Signal)

	go func() {
		stream, err := client.DomainStream(context.Background(), &pb.ExfilDomainsLength{Len: int64(*clientId)})
		if err != nil {
			panic(err.Error())
		}
		for {
			val, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Println("error receive froms erver side stream ")
				return
			}
			if val != nil {
				utils.UpdateDomainBlacklistInCache(val.GetDomain(), utils.DomainNodeAgentCacheBlock{
					TLD:            val.Tld,
					CompleteDomain: val.GetDomain(),
				})
			}
			fmt.Println("got stream ", val)
		}
	}()

	<-reader
	fmt.Println(val)
}
