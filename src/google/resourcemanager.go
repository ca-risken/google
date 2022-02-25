package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-xray-sdk-go/xray"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
)

type resourceManagerServiceClient interface {
	verifyCode(ctx context.Context, gcpProjectID, verificationCode string) (bool, error)
}

type resourceManagerClient struct {
	svc *cloudresourcemanager.Service
}

func newResourceManagerClient(credentialPath string) resourceManagerServiceClient {
	ctx := context.Background()
	svc, err := cloudresourcemanager.NewService(ctx, option.WithCredentialsFile(credentialPath))
	if err != nil {
		appLogger.Fatalf("Failed to create new Cloud Resource Manager service: %+v", err)
	}

	// Remove credential file for Security
	if err := os.Remove(credentialPath); err != nil {
		appLogger.Fatalf("Failed to remove file: path=%s, err=%+v", credentialPath, err)
	}
	return &resourceManagerClient{
		svc: svc,
	}
}

const (
	verificationLabelKey       = "risken"
	verificationErrMsgTemplate = "Faild to verify code, Please check your GCP project label(key=%s), And then the registered verification_code must be the same value.(verification_code=%s)"
)

func (r *resourceManagerClient) verifyCode(ctx context.Context, gcpProjectID, verificationCode string) (bool, error) {
	if verificationCode == "" {
		return true, nil
	}
	// https://cloud.google.com/resource-manager/reference/rest/v1/projects/get
	_, segment := xray.BeginSubsegment(ctx, "GetProject")
	resp, err := r.svc.Projects.Get(gcpProjectID).Context(ctx).Do()
	segment.Close(err)
	if err != nil {
		appLogger.Warnf("Failed to ResourceManager.Projects.Get API, err=%+v", err)
		return false, fmt.Errorf("Failed to ResourceManager.Projects.Get API, err=%+v", err)
	}
	appLogger.Debugf("Got the project info: %+v", resp)
	if v, ok := resp.Labels[verificationLabelKey]; !ok || v != verificationCode {
		return false, fmt.Errorf(verificationErrMsgTemplate, verificationLabelKey, verificationCode)
	}
	return true, nil
}
