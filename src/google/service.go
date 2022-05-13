package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/ca-risken/core/proto/project"
	"github.com/ca-risken/google/pkg/common"
	"github.com/ca-risken/google/proto/google"
	"github.com/vikyd/zero"
	"gorm.io/gorm"
)

type googleService struct {
	repository      googleRepoInterface
	sqs             sqsAPI
	resourceManager resourceManagerServiceClient
	projectClient   project.ProjectServiceClient
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
		UpdatedAt:          data.UpdatedAt.Unix(),
	}
}

func (g *googleService) ListGoogleDataSource(ctx context.Context, req *google.ListGoogleDataSourceRequest) (*google.ListGoogleDataSourceResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	list, err := g.repository.ListGoogleDataSource(ctx, req.GoogleDataSourceId, req.Name)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
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

func convertGCP(data *common.GCP) *google.GCP {
	if data == nil {
		return &google.GCP{}
	}
	gcp := google.GCP{
		GcpId:             data.GCPID,
		Name:              data.Name,
		ProjectId:         data.ProjectID,
		GcpOrganizationId: data.GCPOrganizationID,
		GcpProjectId:      data.GCPProjectID,
		VerificationCode:  data.VerificationCode,
		CreatedAt:         data.CreatedAt.Unix(),
		UpdatedAt:         data.UpdatedAt.Unix(),
	}
	return &gcp
}

func (g *googleService) ListGCP(ctx context.Context, req *google.ListGCPRequest) (*google.ListGCPResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	list, err := g.repository.ListGCP(ctx, req.ProjectId, req.GcpId, req.GcpProjectId)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &google.ListGCPResponse{}, nil
		}
		return nil, err
	}
	data := google.ListGCPResponse{}
	for _, d := range *list {
		data.Gcp = append(data.Gcp, convertGCP(&d))
	}
	return &data, nil
}

func (g *googleService) GetGCP(ctx context.Context, req *google.GetGCPRequest) (*google.GetGCPResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	data, err := g.repository.GetGCP(ctx, req.ProjectId, req.GcpId)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &google.GetGCPResponse{}, nil
		}
		return nil, err
	}
	return &google.GetGCPResponse{Gcp: convertGCP(data)}, nil
}

func (g *googleService) PutGCP(ctx context.Context, req *google.PutGCPRequest) (*google.PutGCPResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	registerd, err := g.repository.UpsertGCP(ctx, req.Gcp)
	if err != nil {
		return nil, err
	}
	return &google.PutGCPResponse{Gcp: convertGCP(registerd)}, nil
}

func (g *googleService) DeleteGCP(ctx context.Context, req *google.DeleteGCPRequest) (*google.Empty, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	list, err := g.repository.ListGoogleDataSource(ctx, 0, "")
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	for _, ds := range *list {
		if err := g.repository.DeleteGCPDataSource(ctx, req.ProjectId, req.GcpId, ds.GoogleDataSourceID); err != nil {
			return nil, err
		}
	}
	if err := g.repository.DeleteGCP(ctx, req.ProjectId, req.GcpId); err != nil {
		return nil, err
	}
	return &google.Empty{}, nil
}

func (g *googleService) ListGCPDataSource(ctx context.Context, req *google.ListGCPDataSourceRequest) (*google.ListGCPDataSourceResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	list, err := g.repository.ListGCPDataSource(ctx, req.ProjectId, req.GcpId)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &google.ListGCPDataSourceResponse{}, nil
		}
		return nil, err
	}
	data := google.ListGCPDataSourceResponse{}
	for _, d := range *list {
		data.GcpDataSource = append(data.GcpDataSource, convertGCPDataSource(&d))
	}
	return &data, nil
}

func convertGCPDataSource(data *gcpDataSource) *google.GCPDataSource {
	if data == nil {
		return &google.GCPDataSource{}
	}
	gcp := google.GCPDataSource{
		GcpId:              data.GCPID,
		GoogleDataSourceId: data.GoogleDataSourceID,
		ProjectId:          data.ProjectID,
		Status:             getStatus(data.Status),
		StatusDetail:       data.StatusDetail,
		CreatedAt:          data.CreatedAt.Unix(),
		UpdatedAt:          data.UpdatedAt.Unix(),
		Name:               data.Name,              // google_data_source.name
		MaxScore:           data.MaxScore,          // google_data_source.max_score
		Description:        data.Description,       // google_data_source.description
		GcpOrganizationId:  data.GCPOrganizationID, // gcp.gcp_organization_id
		GcpProjectId:       data.GCPProjectID,      // gcp.gcp_project_id
	}
	if !zero.IsZeroVal(data.ScanAt) {
		gcp.ScanAt = data.ScanAt.Unix()
	}
	return &gcp
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
	case google.Status_IN_PROGRESS.String():
		return google.Status_IN_PROGRESS
	case google.Status_ERROR.String():
		return google.Status_ERROR
	default:
		return google.Status_UNKNOWN
	}
}

func (g *googleService) GetGCPDataSource(ctx context.Context, req *google.GetGCPDataSourceRequest) (*google.GetGCPDataSourceResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	data, err := g.repository.GetGCPDataSource(ctx, req.ProjectId, req.GcpId, req.GoogleDataSourceId)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &google.GetGCPDataSourceResponse{}, nil
		}
		return nil, err
	}
	return &google.GetGCPDataSourceResponse{GcpDataSource: convertGCPDataSource(data)}, nil
}

func (g *googleService) AttachGCPDataSource(ctx context.Context, req *google.AttachGCPDataSourceRequest) (*google.AttachGCPDataSourceResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	gcp, err := g.repository.GetGCP(ctx, req.ProjectId, req.GcpDataSource.GcpId)
	if err != nil {
		return nil, err
	}
	if ok, err := g.resourceManager.verifyCode(ctx, gcp.GCPProjectID, gcp.VerificationCode); !ok || err != nil {
		return nil, err
	}
	registerd, err := g.repository.UpsertGCPDataSource(ctx, req.GcpDataSource)
	if err != nil {
		return nil, err
	}
	return &google.AttachGCPDataSourceResponse{GcpDataSource: convertGCPDataSource(registerd)}, nil
}

func (g *googleService) DetachGCPDataSource(ctx context.Context, req *google.DetachGCPDataSourceRequest) (*google.Empty, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	err := g.repository.DeleteGCPDataSource(ctx, req.ProjectId, req.GcpId, req.GoogleDataSourceId)
	if err != nil {
		return nil, err
	}
	return &google.Empty{}, nil
}

const (
	cloudAssetDataSourceID  uint32 = 1001
	cloudSploitDataSourceID uint32 = 1002
	sccDataSourceID         uint32 = 1003
	portscanDataSourceID    uint32 = 1004
)

func (g *googleService) InvokeScanGCP(ctx context.Context, req *google.InvokeScanGCPRequest) (*google.Empty, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	gcp, err := g.repository.GetGCP(ctx, req.ProjectId, req.GcpId)
	if err != nil {
		return nil, err
	}
	if ok, err := g.resourceManager.verifyCode(ctx, gcp.GCPProjectID, gcp.VerificationCode); !ok || err != nil {
		return nil, err
	}
	data, err := g.repository.GetGCPDataSource(ctx, req.ProjectId, req.GcpId, req.GoogleDataSourceId)
	if err != nil {
		return nil, err
	}
	msg := &common.GCPQueueMessage{
		GCPID:              data.GCPID,
		ProjectID:          data.ProjectID,
		GoogleDataSourceID: data.GoogleDataSourceID,
		ScanOnly:           req.ScanOnly,
	}
	var resp *sqs.SendMessageOutput
	switch data.GoogleDataSourceID {
	case cloudAssetDataSourceID:
		resp, err = g.sqs.sendMsgForAsset(ctx, msg)
	case cloudSploitDataSourceID:
		resp, err = g.sqs.sendMsgForCloudSploit(ctx, msg)
	case sccDataSourceID:
		resp, err = g.sqs.sendMsgForSCC(ctx, msg)
	case portscanDataSourceID:
		resp, err = g.sqs.sendMsgForPortscan(ctx, msg)
	default:
		return nil, fmt.Errorf("Unknown googleDataSourceID: %d", data.GoogleDataSourceID)
	}
	if err != nil {
		return nil, err
	}
	if _, err = g.repository.UpsertGCPDataSource(ctx, &google.GCPDataSourceForUpsert{
		GcpId:              data.GCPID,
		GoogleDataSourceId: data.GoogleDataSourceID,
		ProjectId:          data.ProjectID,
		Status:             google.Status_IN_PROGRESS,
		StatusDetail:       fmt.Sprintf("Start scan at %+v", time.Now().Format(time.RFC3339)),
		ScanAt:             data.ScanAt.Unix(),
	}); err != nil {
		return nil, err
	}
	appLogger.Infof("Invoke scanned, messageId: %v", resp.MessageId)
	return &google.Empty{}, nil
}

func (g *googleService) InvokeScanAll(ctx context.Context, req *google.InvokeScanAllRequest) (*google.Empty, error) {
	list, err := g.repository.ListGCPDataSourceByDataSourceID(ctx, req.GoogleDataSourceId)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &google.Empty{}, nil
		}
		return nil, err
	}
	for _, gcp := range *list {
		if resp, err := g.projectClient.IsActive(ctx, &project.IsActiveRequest{ProjectId: gcp.ProjectID}); err != nil {
			appLogger.Errorf("Failed to project.IsActive API, err=%+v", err)
			return nil, err
		} else if !resp.Active {
			appLogger.Infof("Skip deactive project, project_id=%d", gcp.ProjectID)
			continue
		}

		if _, err := g.InvokeScanGCP(ctx, &google.InvokeScanGCPRequest{
			GcpId:              gcp.GCPID,
			ProjectId:          gcp.ProjectID,
			GoogleDataSourceId: gcp.GoogleDataSourceID,
			ScanOnly:           true,
		}); err != nil {
			appLogger.Errorf("InvokeScanGCP error occured: gcp_id=%d, err=%+v", gcp.GCPID, err)
			return nil, err
		}
		// TODO delete jitter
		time.Sleep(time.Millisecond * 100) // jitter
	}
	return &google.Empty{}, nil
}
