package grpc

import (
	"fmt"

	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/proto/google"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func NewFindingClient(svcAddr string) (finding.FindingServiceClient, error) {
	conn, err := getGRPCConn(svcAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get GRPC connection: err=%w", err)
	}
	return finding.NewFindingServiceClient(conn), nil
}

func NewAlertClient(svcAddr string) (alert.AlertServiceClient, error) {
	conn, err := getGRPCConn(svcAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get GRPC connection: err=%w", err)
	}
	return alert.NewAlertServiceClient(conn), nil
}

func NewGoogleClient(svcAddr string) (google.GoogleServiceClient, error) {
	conn, err := getGRPCConn(svcAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get GRPC connection: err=%w", err)
	}
	return google.NewGoogleServiceClient(conn), nil
}

func getGRPCConn(addr string) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
