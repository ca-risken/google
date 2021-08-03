package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	asset "cloud.google.com/go/asset/apiv1"
	"github.com/CyberAgent/mimosa-common/pkg/logging"
	"github.com/CyberAgent/mimosa-core/proto/alert"
	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/CyberAgent/mimosa-google/pkg/common"
	"github.com/CyberAgent/mimosa-google/proto/google"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/kelseyhightower/envconfig"
	"google.golang.org/api/iterator"
	assetpb "google.golang.org/genproto/googleapis/cloud/asset/v1"
)

type sqsHandler struct {
	findingClient finding.FindingServiceClient
	alertClient   alert.AlertServiceClient
	googleClient  google.GoogleServiceClient
	assetClient   assetServiceClient

	waitMilliSecPerRequest int
	assetAPIRetryNum       int
	assetAPIRetryWaitSec   int
}

type assetConf struct {
	WaitMilliSecPerRequest int `default:"500" split_words:"true"`
	AssetAPIRetryNum       int `default:"3" split_words:"true"`
	AssetAPIRetryWaitSec   int `default:"30" split_words:"true"`
}

func newHandler() *sqsHandler {
	var conf assetConf
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	appLogger.Infof("Created SQS handler, assetConf=%+v", conf)
	return &sqsHandler{
		findingClient:          newFindingClient(),
		alertClient:            newAlertClient(),
		googleClient:           newGoogleClient(),
		assetClient:            newAssetClient(),
		waitMilliSecPerRequest: conf.WaitMilliSecPerRequest,
		assetAPIRetryNum:       conf.AssetAPIRetryNum,
		assetAPIRetryWaitSec:   conf.AssetAPIRetryWaitSec,
	}
}

type assetFinding struct {
	Asset                *assetpb.ResourceSearchResult     `json:"asset"`
	IAMPolicy            *assetpb.AnalyzeIamPolicyResponse `json:"iam_policy"`
	HasServiceAccountKey bool                              `json:"has_key"`
}

func (s *sqsHandler) HandleMessage(sqsMsg *sqs.Message) error {
	msgBody := aws.StringValue(sqsMsg.Body)
	appLogger.Infof("got message: %s", msgBody)
	msg, err := common.ParseMessage(msgBody)
	if err != nil {
		appLogger.Errorf("Invalid message: msg=%+v, err=%+v", sqsMsg, err)
		return err
	}
	requestID, err := logging.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		appLogger.Warnf("Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}

	appLogger.Infof("start google asset scan, RequestID=%s", requestID)
	ctx := context.Background()
	appLogger.Infof("start get GCP DataSource, RequestID=%s", requestID)
	gcp, err := s.getGCPDataSource(ctx, msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID)
	if err != nil {
		appLogger.Errorf("Failed to get gcp: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
			msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
		return err
	}
	appLogger.Infof("end get GCP DataSource, RequestID=%s", requestID)
	scanStatus := common.InitScanStatus(gcp)

	// Get cloud asset
	appLogger.Infof("start CloudAsset API, RequestID=%s", requestID)
	loopCounter := 0
	assetCounter := 0
	it := s.assetClient.listAsset(ctx, gcp.GcpProjectId)
	for {
		loopCounter++
		appLogger.Debugf("start next CloudAsset API, RequestID=%s", requestID)
		resource, done, err := s.listAssetIterationCallWithRetry(it)
		if done {
			break
		}
		if err != nil {
			appLogger.Errorf("Failed to Coud Asset API: project_id=%d, gcp_id=%d, google_data_source_id=%d, assetCounter=%d, loopCounter=%d, RequestID=%s, err=%+v",
				msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, assetCounter, loopCounter, requestID, err)
			return s.updateScanStatusError(ctx, scanStatus, err.Error())
		}
		assetCounter++
		appLogger.Debugf("end next CloudAsset API, RequestID=%s", requestID)

		f := assetFinding{Asset: resource}
		if isUserServiceAccount(resource.AssetType, resource.Name) {
			email := getShortName(resource.Name)
			hasKey, err := s.assetClient.hasUserManagedKeys(ctx, gcp.GcpProjectId, email)
			if err != nil {
				return s.updateScanStatusError(ctx, scanStatus, err.Error())
			}
			f.HasServiceAccountKey = hasKey
			policy, err := s.assetClient.analyzeServiceAccountPolicy(ctx, gcp.GcpProjectId, email)
			if err != nil {
				return s.updateScanStatusError(ctx, scanStatus, err.Error())
			}
			f.IAMPolicy = policy
		}
		appLogger.Debugf("Got: %+v", resource)
		// Put finding
		appLogger.Debugf("start putFinding, RequestID=%s", requestID)
		if err := s.putFindings(ctx, msg.ProjectID, gcp.GcpProjectId, &f); err != nil {
			appLogger.Errorf("Failed to put findngs: project_id=%d, gcp_id=%d, google_data_source_id=%d, err=%+v",
				msg.ProjectID, msg.GCPID, msg.GoogleDataSourceID, err)
			return s.updateScanStatusError(ctx, scanStatus, err.Error())
		}
		appLogger.Debugf("end putFinding, RequestID=%s", requestID)
		// Control the number of API requests so that they are not exceeded.
		time.Sleep(time.Duration(s.waitMilliSecPerRequest) * time.Millisecond)
	}
	appLogger.Infof("Got %d assets, RequestID=%s", assetCounter, requestID)
	appLogger.Infof("end CloudAsset API, RequestID=%s", requestID)

	appLogger.Infof("start update scan status, RequestID=%s", requestID)
	if err := s.updateScanStatusSuccess(ctx, scanStatus); err != nil {
		return err
	}
	appLogger.Infof("end update scan status, RequestID=%s", requestID)
	appLogger.Infof("end google asset scan, RequestID=%s", requestID)
	if msg.ScanOnly {
		return nil
	}
	return s.analyzeAlert(ctx, msg.ProjectID)
}

func getShortName(name string) string {
	array := strings.Split(name, "/")
	return array[len(array)-1]
}

func (s *sqsHandler) getGCPDataSource(ctx context.Context, projectID, gcpID, googleDataSourceID uint32) (*google.GCPDataSource, error) {
	data, err := s.googleClient.GetGCPDataSource(ctx, &google.GetGCPDataSourceRequest{
		ProjectId:          projectID,
		GcpId:              gcpID,
		GoogleDataSourceId: googleDataSourceID,
	})
	if err != nil {
		return nil, err
	}
	if data == nil || data.GcpDataSource == nil {
		return nil, fmt.Errorf("No gcp data, project_id=%d, gcp_id=%d, google_data_source_id=%d", projectID, gcpID, googleDataSourceID)
	}
	return data.GcpDataSource, nil
}

func (s *sqsHandler) putFindings(ctx context.Context, projectID uint32, gcpProjectID string, f *assetFinding) error {
	score := scoreAsset(f)
	if score == 0.0 {
		// PutResource
		resp, err := s.findingClient.PutResource(ctx, &finding.PutResourceRequest{
			Resource: &finding.ResourceForUpsert{
				ResourceName: common.GetShortResourceName(gcpProjectID, f.Asset.Name),
				ProjectId:    projectID,
			},
		})
		if err != nil {
			appLogger.Errorf("Failed to put resource project_id=%d, assetName=%s, err=%+v", projectID, f.Asset.Name, err)
			return err
		}
		appLogger.Debugf("Success to PutResource, resource_id=%d", resp.Resource.ResourceId)
		return nil
	}

	buf, err := json.Marshal(f)
	if err != nil {
		appLogger.Errorf("Failed to marshal user data, project_id=%d, assetName=%s, err=%+v", projectID, f.Asset.Name, err)
		return err
	}
	// PutFinding
	resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{
		Finding: &finding.FindingForUpsert{
			Description:      fmt.Sprintf("GCP Cloud Asset: %s", f.Asset.DisplayName),
			DataSource:       common.AssetDataSource,
			DataSourceId:     f.Asset.Name,
			ResourceName:     common.GetShortResourceName(gcpProjectID, f.Asset.Name),
			ProjectId:        projectID,
			OriginalScore:    score,
			OriginalMaxScore: 1.0,
			Data:             string(buf),
		},
	})
	if err != nil {
		appLogger.Errorf("Failed to put finding project_id=%d, assetName=%s, err=%+v", projectID, f.Asset.Name, err)
		return err
	}
	// PutFindingTag
	s.tagFinding(ctx, common.TagGCP, resp.Finding.FindingId, resp.Finding.ProjectId)
	s.tagFinding(ctx, common.TagAssetInventory, resp.Finding.FindingId, resp.Finding.ProjectId)
	s.tagFinding(ctx, gcpProjectID, resp.Finding.FindingId, resp.Finding.ProjectId)
	if isUserServiceAccount(f.Asset.AssetType, f.Asset.Name) {
		s.tagFinding(ctx, common.TagServiceAccount, resp.Finding.FindingId, resp.Finding.ProjectId)
	}
	appLogger.Debugf("Success to PutFinding, finding_id=%d", resp.Finding.FindingId)
	return nil
}

func (s *sqsHandler) tagFinding(ctx context.Context, tag string, findingID uint64, projectID uint32) error {
	_, err := s.findingClient.TagFinding(ctx, &finding.TagFindingRequest{
		ProjectId: projectID,
		Tag: &finding.FindingTagForUpsert{
			FindingId: findingID,
			ProjectId: projectID,
			Tag:       tag,
		}})
	if err != nil {
		appLogger.Errorf("Failed to TagFinding, finding_id=%d, tag=%s, error=%+v", findingID, tag, err)
		return err
	}
	return nil
}

func (s *sqsHandler) updateScanStatusError(ctx context.Context, putData *google.AttachGCPDataSourceRequest, statusDetail string) error {
	putData.GcpDataSource.Status = google.Status_ERROR
	statusDetail = common.CutString(statusDetail, 200)
	putData.GcpDataSource.StatusDetail = statusDetail
	return s.updateScanStatus(ctx, putData)
}

func (s *sqsHandler) updateScanStatusSuccess(ctx context.Context, putData *google.AttachGCPDataSourceRequest) error {
	putData.GcpDataSource.Status = google.Status_OK
	putData.GcpDataSource.StatusDetail = ""
	return s.updateScanStatus(ctx, putData)
}

func (s *sqsHandler) updateScanStatus(ctx context.Context, putData *google.AttachGCPDataSourceRequest) error {
	resp, err := s.googleClient.AttachGCPDataSource(ctx, putData)
	if err != nil {
		return err
	}
	appLogger.Infof("Success to update GCP DataSource status, response=%+v", resp)
	return nil
}

func (s *sqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}

const (
	userServiceAccountEmailPattern string = ".iam.gserviceaccount.com"

	// Basic roles: https://cloud.google.com/iam/docs/understanding-roles
	roleOwner  string = "roles/owner"
	roleEditor string = "roles/editor"
)

func isUserServiceAccount(assetType, name string) bool {
	return assetType == assetTypeServiceAccount && strings.HasSuffix(name, userServiceAccountEmailPattern)
}

func scoreAsset(f *assetFinding) float32 {
	if f == nil || f.Asset == nil {
		return 0.0
	}
	if isUserServiceAccount(f.Asset.AssetType, f.Asset.Name) {
		if f.IAMPolicy == nil || f.IAMPolicy.MainAnalysis == nil || f.IAMPolicy.MainAnalysis.AnalysisResults == nil {
			return 0.0
		}
		if !f.HasServiceAccountKey {
			return 0.1
		}
		for _, p := range f.IAMPolicy.MainAnalysis.AnalysisResults {
			if p.IamBinding == nil {
				continue
			}
			if p.IamBinding.Role == roleOwner || p.IamBinding.Role == roleEditor {
				return 0.8 // the serviceAccount has Admin role.
			}
		}
		return 0.1
	}
	return 0.0
}

func (s *sqsHandler) listAssetIterationCallWithRetry(it *asset.ResourceSearchResultIterator) (resource *assetpb.ResourceSearchResult, done bool, err error) {
	for i := 0; i <= s.assetAPIRetryNum; i++ {
		if i > 0 {
			time.Sleep(time.Duration(s.assetAPIRetryWaitSec+i) * time.Second)
		}
		resource, err = it.Next() // Call API
		if err == iterator.Done {
			return resource, true, nil
		}
		if err == nil {
			return resource, false, nil
		}
		// https://cloud.google.com/apis/design/errors#retrying_errors
		// > For 429 RESOURCE_EXHAUSTED errors, the client may retry at the higher level with minimum 30s delay.
		// > Such retries are only useful for long running background jobs.
		if i < s.assetAPIRetryNum {
			appLogger.Warnf("Failed to Cloud Asset API, But retry call API after %d seconds..., retry=%d/%d, API Result=%+v, err=%+v",
				s.assetAPIRetryWaitSec+i, i+1, s.assetAPIRetryNum, resource, err)
		}
	}
	return nil, false, fmt.Errorf("Failed to call CloudAsset API (Retry %d times , But all failed), err=%+v", s.assetAPIRetryNum, err)
}
