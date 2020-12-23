package main

import (
	"context"
	"strings"
	"time"

	"github.com/CyberAgent/mimosa-google/pkg/common"
	"github.com/CyberAgent/mimosa-google/proto/google"
	"github.com/jinzhu/gorm"
	"github.com/vikyd/zero"
)

type googleService struct {
	repository googleRepoInterface
	sqs        sqsAPI
}

func newGoogleService() google.GoogleServiceServer {
	return &googleService{
		repository: newGoogleRepository(),
		sqs:        newSQSClient(),
	}
}

func convertGoogleDataSource(data *common.GoogleDataSource) *google.GoogleDataSource {
	if data == nil {
		return &google.GoogleDataSource{}
	}
	return &google.GoogleDataSource{
		GoogleDataSourceId: data.GoogleDataSourceID,
		Name:               data.Name,
		Description:        data.Description,
		MaxScore:           data.MaxScore,
		CreatedAt:          data.CreatedAt.Unix(),
		UpdatedAt:          data.CreatedAt.Unix(),
	}
}

func (g *googleService) ListGoogleDataSource(ctx context.Context, req *google.ListGoogleDataSourceRequest) (*google.ListGoogleDataSourceResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	list, err := g.repository.ListGoogleDataSource(req.GoogleDataSourceId, req.Name)
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return &google.ListGoogleDataSourceResponse{}, nil
		}
		return nil, err
	}
	data := google.ListGoogleDataSourceResponse{}
	for _, d := range *list {
		data.GoogleDataSource = append(data.GoogleDataSource, convertGoogleDataSource(&d))
	}
	return &data, nil
}

func convertGoogleGCP(data *common.GoogleGCP) *google.GCP {
	if data == nil {
		return &google.GCP{}
	}
	gcp := google.GCP{
		GcpId:              data.GCPID,
		GoogleDataSourceId: data.GoogleDataSourceID,
		Name:               data.Name,
		ProjectId:          data.ProjectID,
		GcpOrganizationId:  data.GCPOrganizationID,
		GcpProjectId:       data.GCPProjectID,
		Status:             getStatus(data.Status),
		StatusDetail:       data.StatusDetail,
		CreatedAt:          data.CreatedAt.Unix(),
		UpdatedAt:          data.CreatedAt.Unix(),
	}
	if !zero.IsZeroVal(data.ScanAt) {
		gcp.ScanAt = data.ScanAt.Unix()
	}
	return &gcp
}

func (g *googleService) ListGCP(ctx context.Context, req *google.ListGCPRequest) (*google.ListGCPResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	list, err := g.repository.ListGCP(req.ProjectId, req.GoogleDataSourceId, req.GcpId)
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return &google.ListGCPResponse{}, nil
		}
		return nil, err
	}
	data := google.ListGCPResponse{}
	for _, d := range *list {
		data.Gcp = append(data.Gcp, convertGoogleGCP(&d))
	}
	return &data, nil
}

func (g *googleService) GetGCP(ctx context.Context, req *google.GetGCPRequest) (*google.GetGCPResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	data, err := g.repository.GetGCP(req.ProjectId, req.GcpId)
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return &google.GetGCPResponse{}, nil
		}
		return nil, err
	}
	return &google.GetGCPResponse{Gcp: convertGoogleGCP(data)}, nil
}

func (g *googleService) PutGCP(ctx context.Context, req *google.PutGCPRequest) (*google.PutGCPResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	registerd, err := g.repository.UpsertGCP(req.Gcp)
	if err != nil {
		return nil, err
	}
	return &google.PutGCPResponse{Gcp: convertGoogleGCP(registerd)}, nil
}

func (g *googleService) DeleteGCP(ctx context.Context, req *google.DeleteGCPRequest) (*google.Empty, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	err := g.repository.DeleteGCP(req.ProjectId, req.GcpId)
	if err != nil {
		return nil, err
	}
	return &google.Empty{}, nil
}

func getStatus(s string) google.Status {
	statusKey := strings.ToUpper(s)
	if _, ok := google.Status_value[statusKey]; !ok {
		return google.Status_UNKNOWN
	}
	switch statusKey {
	case google.Status_OK.String():
		return google.Status_OK
	case google.Status_CONFIGURED.String():
		return google.Status_CONFIGURED
	case google.Status_NOT_CONFIGURED.String():
		return google.Status_NOT_CONFIGURED
	case google.Status_ERROR.String():
		return google.Status_ERROR
	default:
		return google.Status_UNKNOWN
	}
}

func (g *googleService) InvokeScanGCP(ctx context.Context, req *google.InvokeScanGCPRequest) (*google.Empty, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	data, err := g.repository.GetGCP(req.ProjectId, req.GcpId)
	if err != nil {
		return nil, err
	}
	resp, err := g.sqs.sendMsgForGCP(&common.GCPQueueMessage{
		GCPID:     data.GCPID,
		ProjectID: data.ProjectID,
	})
	if err != nil {
		return nil, err
	}
	appLogger.Infof("Invoke scanned, messageId: %v", resp.MessageId)
	return &google.Empty{}, nil
}

func (g *googleService) InvokeScanAll(ctx context.Context, _ *google.Empty) (*google.Empty, error) {
	list, err := g.repository.ListGCP(0, 0, 0)
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
			return &google.Empty{}, nil
		}
		return nil, err
	}
	for _, gcp := range *list {
		if zero.IsZeroVal(gcp.ProjectID) || zero.IsZeroVal(gcp.GoogleDataSourceID) {
			continue
		}
		if _, err := g.InvokeScanGCP(ctx, &google.InvokeScanGCPRequest{
			GcpId:     gcp.GCPID,
			ProjectId: gcp.ProjectID,
		}); err != nil {
			// エラーログはいて握りつぶす（すべてのスキャナ登録しきる）
			appLogger.Errorf("InvokeScanGCP error occured: gcp_id=%d, err=%+v", gcp.GCPID, err)
		}
		time.Sleep(time.Millisecond * 100) // jitter
	}
	return &google.Empty{}, nil
}
