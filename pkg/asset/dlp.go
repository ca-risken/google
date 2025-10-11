package asset

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/ca-risken/common/pkg/dlp"
	"google.golang.org/api/iterator"
)

type bucketFileCandidate struct {
	BucketName string
	ObjectName string
	Size       int64
	Updated    *time.Time
}

func (a *assetClient) dlpScanBucket(ctx context.Context, bucketName string, prevResult *dlp.ScanResult, fullScan bool) (*dlp.ScanResult, error) {
	if a.dlpConfig == nil {
		return nil, fmt.Errorf("dlp config is not initialized")
	}

	a.logger.Infof(ctx, "start DLP scan for bucket=%s, full_scan=%t", bucketName, fullScan)

	candidates, err := a.collectBucketCandidateFiles(ctx, bucketName)
	if err != nil {
		return nil, fmt.Errorf("failed to collect file candidates for bucket %s: %w", bucketName, err)
	}
	a.logger.Debugf(ctx, "collected %d file candidates for bucket=%s", len(candidates), bucketName)

	var filteredCandidates []bucketFileCandidate
	var cachedFindings []dlp.Finding
	var scanResults *dlp.ScanResult

	if prevResult != nil && prevResult.ScanTime > 0 && !fullScan {
		filteredCandidates, cachedFindings = a.filterCandidatesWithCache(ctx, bucketName, candidates, prevResult)
		scanResults = prevResult
	} else {
		filteredCandidates = candidates
		if fullScan && prevResult != nil {
			a.logger.Debugf(ctx, "ignoring cached DLP result due to full scan request, bucket=%s", bucketName)
		}
	}

	selectedFiles := a.selectFilesToScan(ctx, filteredCandidates)
	if len(selectedFiles) == 0 {
		a.logger.Debugf(ctx, "no DLP targets for bucket=%s after filtering", bucketName)
		if scanResults != nil {
			return scanResults, nil
		}
		return prevResult, nil
	}

	newScanResults, err := a.downloadAndScanFiles(ctx, selectedFiles, bucketName)
	if err != nil {
		a.logger.Warnf(ctx, "failed to download and scan files for bucket=%s: %+v", bucketName, err)
	} else if newScanResults != nil {
		scanResults = newScanResults
	}

	if scanResults == nil {
		// No new scan succeeded, fallback to previous result (may be nil)
		scanResults = prevResult
	}

	if scanResults == nil {
		return nil, nil
	}

	if len(cachedFindings) > 0 {
		filePaths := map[string]struct{}{}
		for _, finding := range scanResults.Findings {
			filePaths[finding.FilePath] = struct{}{}
		}
		for _, finding := range cachedFindings {
			if _, ok := filePaths[finding.FilePath]; ok {
				continue
			}
			scanResults.Findings = append(scanResults.Findings, finding)
		}
		a.logger.Debugf(ctx, "merged %d cached DLP findings for bucket=%s", len(cachedFindings), bucketName)
	}

	return scanResults, nil
}

func (a *assetClient) collectBucketCandidateFiles(ctx context.Context, bucketName string) ([]bucketFileCandidate, error) {
	var candidates []bucketFileCandidate
	it := a.gcs.Bucket(bucketName).Objects(ctx, &storage.Query{})
	count := 0
	for {
		attr, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list objects: %w", err)
		}

		if count >= a.dlpConfig.MaxScanFiles {
			a.logger.Warnf(ctx, "reached maximum file metadata limit (%d files) for bucket=%s", a.dlpConfig.MaxScanFiles, bucketName)
			break
		}

		if strings.HasSuffix(attr.Name, "/") {
			continue
		}

		candidate := bucketFileCandidate{
			BucketName: bucketName,
			ObjectName: attr.Name,
			Size:       attr.Size,
		}
		if !attr.Updated.IsZero() {
			updated := attr.Updated
			candidate.Updated = &updated
		}
		candidates = append(candidates, candidate)
		count++
	}
	return candidates, nil
}

func (a *assetClient) selectFilesToScan(ctx context.Context, candidates []bucketFileCandidate) []bucketFileCandidate {
	if len(candidates) == 0 {
		return candidates
	}

	var selected []bucketFileCandidate
	var totalSize int64

	for _, candidate := range candidates {
		if len(selected) >= a.dlpConfig.MaxScanFiles {
			a.logger.Warnf(ctx, "reached maximum DLP scan file count (%d)", a.dlpConfig.MaxScanFiles)
			break
		}
		if totalSize+candidate.Size > a.dlpConfig.GetMaxScanSizeBytes() {
			a.logger.Warnf(ctx, "reached maximum DLP scan size limit (%d MB)", a.dlpConfig.MaxScanSizeMB)
			break
		}
		if candidate.Size > a.dlpConfig.GetMaxSingleFileSizeBytes() {
			a.logger.Debugf(ctx, "skip object=%s due to size %.2fMB > max_single_file_size=%dMB",
				candidate.ObjectName, float64(candidate.Size)/(1024*1024), a.dlpConfig.MaxSingleFileSizeMB)
			continue
		}
		if slices.ContainsFunc(a.dlpConfig.ExcludeFilePatterns, func(pattern string) bool {
			return strings.Contains(candidate.ObjectName, pattern)
		}) {
			a.logger.Debugf(ctx, "skip object=%s due to exclude pattern match", candidate.ObjectName)
			continue
		}

		selected = append(selected, candidate)
		totalSize += candidate.Size
	}

	a.logger.Debugf(ctx, "selected %d objects for DLP scan (total=%.2fMB)", len(selected), float64(totalSize)/(1024*1024))
	return selected
}

func (a *assetClient) downloadAndScanFiles(ctx context.Context, candidates []bucketFileCandidate, bucketName string) (*dlp.ScanResult, error) {
	if len(candidates) == 0 {
		return nil, nil
	}

	tempDir, err := createTempDir()
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() {
		if cleanupErr := cleanupTempDir(tempDir); cleanupErr != nil {
			a.logger.Warnf(ctx, "failed to cleanup temp directory: %+v", cleanupErr)
		}
	}()

	if err := a.downloadObjects(ctx, candidates, tempDir); err != nil {
		return nil, fmt.Errorf("failed to download objects: %w", err)
	}

	scanner := dlp.NewScanner(a.dlpConfig)
	result, err := scanner.ScanDirectory(ctx, tempDir, bucketName, len(candidates))
	if err != nil {
		return nil, fmt.Errorf("failed to execute DLP scanner: %w", err)
	}
	return result, nil
}

func (a *assetClient) downloadObjects(ctx context.Context, candidates []bucketFileCandidate, tempDir string) error {
	for idx, candidate := range candidates {
		a.logger.Debugf(ctx, "downloading object (%d/%d): %s", idx+1, len(candidates), candidate.ObjectName)

		reader, err := a.gcs.Bucket(candidate.BucketName).Object(candidate.ObjectName).NewReader(ctx)
		if err != nil {
			a.logger.Warnf(ctx, "failed to open object=%s from bucket=%s: %+v", candidate.ObjectName, candidate.BucketName, err)
			continue
		}

		safePath := sanitizeObjectPath(candidate.ObjectName)
		localPath := filepath.Join(tempDir, safePath)
		if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
			reader.Close()
			a.logger.Warnf(ctx, "failed to create local directory for %s: %+v", localPath, err)
			continue
		}

		if err := saveToLocalFile(reader, localPath); err != nil {
			a.logger.Warnf(ctx, "failed to save object=%s to %s: %+v", candidate.ObjectName, localPath, err)
			continue
		}
	}
	return nil
}

func (a *assetClient) filterCandidatesWithCache(
	ctx context.Context,
	bucketName string,
	candidates []bucketFileCandidate,
	previousResult *dlp.ScanResult,
) ([]bucketFileCandidate, []dlp.Finding) {
	if previousResult == nil {
		return candidates, nil
	}

	var target []bucketFileCandidate
	var cached []dlp.Finding

	fileResults := make(map[string]dlp.Finding)
	for _, finding := range previousResult.Findings {
		fileResults[finding.FilePath] = finding
	}

	for _, candidate := range candidates {
		filePath := fmt.Sprintf("%s/%s", bucketName, candidate.ObjectName)
		if candidate.Updated != nil && candidate.Updated.Unix() < previousResult.ScanTime {
			if prevFinding, exists := fileResults[filePath]; exists {
				cached = append(cached, prevFinding)
				a.logger.Debugf(ctx, "reuse cached DLP finding for %s (updated=%v < scan_at=%v)",
					candidate.ObjectName, candidate.Updated, time.Unix(previousResult.ScanTime, 0))
				continue
			}
			target = append(target, candidate)
			continue
		}
		// Unknown updated timestamp -> scan
		if candidate.Updated == nil {
			a.logger.Debugf(ctx, "object=%s has no updated timestamp, include for scan", candidate.ObjectName)
		}
		target = append(target, candidate)
	}

	a.logger.Infof(ctx, "DLP candidate filter result for bucket=%s: scan=%d, cached=%d", bucketName, len(target), len(cached))
	return target, cached
}

func sanitizeObjectPath(objectName string) string {
	clean := strings.ReplaceAll(objectName, "\\", "/")
	parts := strings.Split(clean, "/")
	for i, part := range parts {
		safe := strings.ReplaceAll(part, "..", "_")
		replacer := []string{":", "_", "*", "_", "?", "_", "<", "_", ">", "_", "|", "_", "\"", "_"}
		for idx := 0; idx < len(replacer); idx += 2 {
			safe = strings.ReplaceAll(safe, replacer[idx], replacer[idx+1])
		}
		if safe == "" || safe == "." {
			safe = "unnamed"
		}
		parts[i] = safe
	}
	result := strings.Join(parts, "/")
	if result == "" {
		return "unnamed_file"
	}
	return result
}

func saveToLocalFile(reader io.ReadCloser, localPath string) error {
	defer reader.Close()

	localFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file %s: %w", localPath, err)
	}
	defer localFile.Close()

	if _, err := io.Copy(localFile, reader); err != nil {
		return fmt.Errorf("failed to copy object content: %w", err)
	}
	return nil
}

func createTempDir() (string, error) {
	dir, err := os.MkdirTemp("", "dlp-scan-")
	if err != nil {
		return "", err
	}
	return dir, nil
}

func cleanupTempDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("temp directory path is empty")
	}
	return os.RemoveAll(dir)
}
