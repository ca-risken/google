package main

import (
	"fmt"
	"net"

	"github.com/CyberAgent/mimosa-google/proto/google"
	"github.com/kelseyhightower/envconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type codeConfig struct {
	Port string `default:"11001"`
}

func main() {
	var conf codeConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%s", conf.Port))
	if err != nil {
		appLogger.Fatal(err)
	}

	server := grpc.NewServer()
	googleServer := newGoogleService()
	google.RegisterGoogleServiceServer(server, googleServer)

	reflection.Register(server) // enable reflection API
	appLogger.Infof("Starting gRPC server at :%s", conf.Port)
	if err := server.Serve(l); err != nil {
		appLogger.Fatalf("Failed to gRPC serve: %v", err)
	}
}
