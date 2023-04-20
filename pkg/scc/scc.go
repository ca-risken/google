package scc

import (
	"context"
	"fmt"
	"os"
	"time"

	scc "cloud.google.com/go/securitycenter/apiv1"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/cenkalti/backoff/v4"
	"google.golang.org/api/option"
	sccpb "google.golang.org/genproto/googleapis/cloud/securitycenter/v1"
)

const (
	maxIterationFetch = 1000
)

type SCCServiceClient interface {
	listFinding(ctx context.Context, gcpProjectID string) *scc.ListFindingsResponse_ListFindingsResultIterator
	iterationFetchFindingsWithRetry(
		ctx context.Context,
		it *scc.ListFindingsResponse_ListFindingsResultIterator,
		nextPageToken string,
	) (*sccIterationResult, error)
}

type SCCClient struct {
	client  *scc.Client
	logger  logging.Logger
	retryer backoff.BackOff
}

func NewSCCClient(ctx context.Context, credentialPath string, l logging.Logger) (SCCServiceClient, error) {
	c, err := scc.NewClient(ctx, option.WithCredentialsFile(credentialPath))
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate for Google API client: %w", err)
	}
	// Remove credential file for Security
	if err := os.Remove(credentialPath); err != nil {
		return nil, fmt.Errorf("failed to remove file: path=%s, err=%w", credentialPath, err)
	}
	return &SCCClient{
		client:  c,
		logger:  l,
		retryer: backoff.WithMaxRetries(backoff.NewExponentialBackOff(), 10),
	}, nil
}

func (s *SCCClient) listFinding(ctx context.Context, gcpProjectID string) *scc.ListFindingsResponse_ListFindingsResultIterator {
	// https://pkg.go.dev/google.golang.org/api/securitycenter/v1
	return s.client.ListFindings(ctx, &sccpb.ListFindingsRequest{
		Parent: fmt.Sprintf("projects/%s/sources/-", gcpProjectID),
	})
}

type sccIterationResult struct {
	findings []*sccpb.ListFindingsResponse_ListFindingsResult
	token    string
}

func (s *SCCClient) iterationFetchFindingsWithRetry(
	ctx context.Context,
	it *scc.ListFindingsResponse_ListFindingsResultIterator,
	nextPageToken string,
) (
	*sccIterationResult, error,
) {
	operation := func() (*sccIterationResult, error) {
		return s.iterationFetchFindings(it, nextPageToken)
	}
	return backoff.RetryNotifyWithData(operation, s.retryer, s.newRetryLogger(ctx, "iterationFetchFindings"))
}

func (s *SCCClient) iterationFetchFindings(
	it *scc.ListFindingsResponse_ListFindingsResultIterator,
	nextPageToken string,
) (
	*sccIterationResult, error,
) {
	findings, token, err := it.InternalFetch(maxIterationFetch, nextPageToken)
	if err != nil {
		return nil, err
	}
	return &sccIterationResult{
		findings: findings,
		token:    token,
	}, nil
}

func (s *SCCClient) newRetryLogger(ctx context.Context, funcName string) func(error, time.Duration) {
	return func(err error, t time.Duration) {
		s.logger.Warnf(ctx, "[RetryLogger] %s error: duration=%+v, err=%+v", funcName, t, err)
	}
}

func scoreSCC(f *sccpb.Finding) float32 {
	if f.State != sccpb.Finding_ACTIVE {
		return 0.1
	}
	switch f.Severity {
	case sccpb.Finding_CRITICAL:
		return 0.9
	case sccpb.Finding_HIGH:
		return 0.6
	case sccpb.Finding_MEDIUM:
		return 0.3
	case sccpb.Finding_LOW:
		return 0.1
	}
	return 0.0
}
