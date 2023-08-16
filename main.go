package main

import (
	"log"
    "net"

	"github.com/Encedeus/skyhook/container"
	docker "github.com/docker/docker/client"
	"google.golang.org/grpc"
    protoapi "github.com/Encedeus/protobuf/panel"
)


func main() {
    client, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
    if err != nil {
        log.Fatalf("failed connecting to Docker Engine: %e", err)
    }
    defer client.Close()

    cs := container.ContainerServer{
        Client: client,
    }

    server := grpc.NewServer()
    protoapi.RegisterContainerServer(server, cs)

    listen, err := net.Listen("tcp", ":8080")
    if err != nil {
        log.Fatalf("failed creating gRPC server listener: %e", err)
    }

    err = server.Serve(listen)
    if err != nil {
        log.Fatalf("failed starting gRPC server: %e", err)
    }
}
