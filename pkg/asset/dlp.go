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

func (a *assetClient) dlpScanBucket(ctx context.Context, bucketName string, previous *bucketDLPScan, fullScan bool, accessType string) (*bucketDLPScan, error) {
	authenticatedRead := accessType == allAuthenticatedUsers
	if previous != nil && previous.AuthenticatedRead != authenticatedRead {
		// Access changes can expose objects without changing their update times.
		previous = nil
	}
	fallback := previous
	if fullScan {
		previous = nil
	}
	result, err := scanDLPFiles(ctx, a.dlpScanner, bucketName, func(ctx context.Context, visit func(dlpObject)) error {
		return a.listDLPObjects(ctx, bucketName, authenticatedRead, visit)
	}, previous, time.Now())
	if err != nil {
		return fallback, err
	}
	result.AuthenticatedRead = authenticatedRead
	return result, nil
}

func (a *assetClient) listDLPObjects(ctx context.Context, bucket string, authenticatedRead bool, visit func(dlpObject)) error {
	items := a.gcs.Bucket(bucket).Objects(ctx, &storage.Query{})
	items.PageInfo().MaxSize = 1000
	publicBucket := a.publicGCS.Bucket(bucket)
	authenticatedBucket := a.gcs.Bucket(bucket)
	for {
		item, err := items.Next()
		if errors.Is(err, iterator.Done) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to list objects in bucket %s: %w", bucket, err)
		}
		if strings.HasSuffix(item.Name, "/") {
			continue
		}

		object := publicBucket.Object(item.Name).Generation(item.Generation)
		target := dlpObject{
			Name: item.Name, Size: item.Size, Updated: item.Updated,
			Open: func(ctx context.Context) (io.ReadCloser, error) {
				return object.NewReader(ctx)
			},
		}
		if authenticatedRead {
			object := authenticatedBucket.Object(item.Name).Generation(item.Generation)
			target.OpenAuthenticated = func(ctx context.Context) (io.ReadCloser, error) {
				return object.NewReader(ctx)
			}
		}
		visit(target)
	}
}
