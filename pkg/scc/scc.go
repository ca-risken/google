package scc

import (
	"context"
	"fmt"
	"os"
	"slices"
	"time"

	sccv2 "cloud.google.com/go/securitycenter/apiv2"
	sccv2pb "cloud.google.com/go/securitycenter/apiv2/securitycenterpb"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/cenkalti/backoff/v4"
	"google.golang.org/api/option"
)

const (
	maxIterationFetch = 1000
)

type SCCServiceClient interface {
	listFinding(ctx context.Context, gcpProjectID string, includeAllSeverity bool) *sccv2.ListFindingsResponse_ListFindingsResultIterator

	iterationFetchFindingsWithRetry(
		ctx context.Context,
		it *sccv2.ListFindingsResponse_ListFindingsResultIterator,
		nextPageToken string,
	) (*sccIterationResult, error)
}

type SCCClient struct {
	client  *sccv2.Client
	logger  logging.Logger
	retryer backoff.BackOff
}

func NewSCCClient(ctx context.Context, credentialPath string, l logging.Logger) (SCCServiceClient, error) {
	c, err := sccv2.NewClient(ctx, option.WithCredentialsFile(credentialPath))
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

func (s *SCCClient) listFinding(ctx context.Context, gcpProjectID string, includeLowSeverity bool) *sccv2.ListFindingsResponse_ListFindingsResultIterator {
	// https://pkg.go.dev/cloud.google.com/go/securitycenter/apiv2/securitycenterpb#ListFindingsRequest
	defaultFilter := `state="ACTIVE" AND NOT mute="MUTED"`
	severity := `severity="CRITICAL" OR severity="HIGH" OR severity="MEDIUM"`
	if includeLowSeverity {
		severity += ` OR severity="LOW"`
	}
	filter := fmt.Sprintf("%s AND (%s)", defaultFilter, severity)
	return s.client.ListFindings(ctx, &sccv2pb.ListFindingsRequest{
		Parent: fmt.Sprintf("projects/%s/sources/-", gcpProjectID),
		Filter: filter,
	})
}

type sccIterationResult struct {
	findings []*sccv2pb.ListFindingsResponse_ListFindingsResult
	token    string
}

func (s *SCCClient) iterationFetchFindingsWithRetry(
	ctx context.Context,
	it *sccv2.ListFindingsResponse_ListFindingsResultIterator,
	nextPageToken string,
) (
	*sccIterationResult, error,
) {
	operation := func() (*sccIterationResult, error) {
		return s.iterationFetchFindings(it, nextPageToken)
	}
	return backoff.RetryNotifyWithData(operation, s.retryer, s.newRetryLogger(ctx, "iterationFetchFindingsV2"))
}

func (s *SCCClient) iterationFetchFindings(
	it *sccv2.ListFindingsResponse_ListFindingsResultIterator,
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

func (s *SqsHandler) scoreSCC(f *sccv2pb.Finding) float32 {
	findingClass := f.GetFindingClass().String()
	if slices.Contains(s.reduceScoreFindingClass, findingClass) {
		return 0.1
	}
	switch f.Severity {
	case sccv2pb.Finding_CRITICAL:
		return 0.9
	case sccv2pb.Finding_HIGH:
		return 0.6
	case sccv2pb.Finding_MEDIUM:
		return 0.3
	case sccv2pb.Finding_LOW:
		return 0.1
	}
	return 0.0
}
