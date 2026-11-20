package asset

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

func (a *assetClient) dlpScanBucket(ctx context.Context, bucketName string, previous *bucketDLPScan, fullScan bool) (*bucketDLPScan, error) {
	started := time.Now()
	objects, err := a.collectDLPObjects(ctx, bucketName)
	if err != nil {
		return previous, err
	}
	if fullScan {
		previous = nil
	}
	return scanDLPFiles(ctx, a.dlpScanner, bucketName, objects, previous, started), nil
}

func (a *assetClient) collectDLPObjects(ctx context.Context, bucket string) ([]dlpObject, error) {
	items := a.gcs.Bucket(bucket).Objects(ctx, &storage.Query{})
	var objects []dlpObject
	for {
		item, err := items.Next()
		if errors.Is(err, iterator.Done) {
			return objects, nil
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list objects in bucket %s: %w", bucket, err)
		}
		if strings.HasSuffix(item.Name, "/") {
			continue
		}

		object := a.publicGCS.Bucket(bucket).Object(item.Name).Generation(item.Generation)
		objects = append(objects, dlpObject{
			Name: item.Name, Size: item.Size, Updated: item.Updated,
			Open: func(ctx context.Context) (io.ReadCloser, error) {
				return object.NewReader(ctx)
			},
		})
	}
}
