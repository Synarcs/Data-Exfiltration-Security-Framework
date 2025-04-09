package rpc

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	pb "github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/rpc/pb"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
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
		utils.Log(err)
	}

	var reader chan os.Signal = make(chan os.Signal)

	ctx := context.Background()
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(time.Second*30))
	go func(ctx context.Context, cancel context.CancelFunc) {
		var domains []string = []string{"google.com", "apple.com"}
		stream, err := client.GetExfilDomains(ctx, &pb.ExfilDomains{Domain: domains[0]})
		if err != nil {
			panic(err.Error())
		}
		for {

			val, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				utils.Log("error receive froms erver side stream ", err)
				return
			}
			if val != nil {
				utils.Log(val.Domain, val.Tld)
			}
			fmt.Println(val.Status)
		}
	}(ctx, cancel)

	<-reader
	fmt.Println(val)
}
