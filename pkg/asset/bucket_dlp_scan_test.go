package asset

import (
	"context"
	json "encoding/json/v2"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"github.com/ca-risken/common/pkg/dlp"
	"github.com/google/go-cmp/cmp"
	cloudresourcemanagerv1 "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

func TestBucketDLPScanRetainsPreviousFileResponses(t *testing.T) {
	t.Parallel()

	const stored = `{
		"resource_name":"example.test",
		"scan_time":1700000000,
		"total_files":1,
		"total_severity":"HIGH",
		"severity_reason":"previous severity",
		"test_data":null,
		"sensitive_objects":[{"object":"old.wav","complete":false,"content_kind":"UNSPECIFIED","content_type":["PII"]}],
		"findings":[{"file_path":"example.test/retained/契約 #+%.txt","type":"PII","matches":["legacy@example.test"]},{"file_path":"example.test/retained/契約 #+%.txt","type":"Credential"}],
		"object_scans":[{"object":"old.csv","input":"text","complete":true,"sensitivity":2}],
		"pdf_scans":[{"object":"old.pdf","complete":true,"total_pages":1,"pages":[
			{"number":1,"input":"text","sensitivity":1,"categories":[4],"test_data":2}
		]},{"object":"unknown.pdf","complete":false},{"object":"deleted.pdf","complete":false}]
	}`
	previous, err := parseDLPScanData(`{"dlp_scan":` + stored + `}`)
	if err != nil {
		t.Fatal(err)
	}

	cutoff := time.Unix(previous.ScanTime, 0)
	opens := 0
	objects := []dlpObject{
		{Name: "old.wav", Updated: cutoff},
		{Name: "retained/契約 #+%.txt", Updated: cutoff},
		{Name: "old.csv", Updated: cutoff},
		{Name: "old.pdf", Updated: cutoff},
		{Name: "unknown.pdf", Updated: cutoff},
		{
			Name: "new.zip", Updated: cutoff.Add(time.Minute),
			Open: func(context.Context) (io.ReadCloser, error) {
				opens++
				return io.NopCloser(strings.NewReader("PK\x03\x04\x00")), nil
			},
		},
	}
	scanner := dlp.NewScanner(nil, &dlp.Config{})
	started := cutoff.Add(time.Hour)
	got := scanDLPTestFiles(t, scanner, "example.test", objects, previous, started).withSummary()
	if got.ScanTime != started.Unix()-1 || opens != 1 {
		t.Fatalf("scan time = %d, opened files = %d", got.ScanTime, opens)
	}
	wantFiles := []bucketFileScan{
		{
			Object: "old.wav",
			URL:    "https://storage.googleapis.com/example.test/old.wav",
			FindingFile: dlp.FindingFile{
				Sensitivity: new(true), ContentType: []string{"PII"}, ContentKind: "UNSPECIFIED",
			},
		},
		{
			Object: "old.pdf",
			URL:    "https://storage.googleapis.com/example.test/old.pdf",
			FindingFile: dlp.FindingFile{
				Input: "pdf", Complete: true, Sensitivity: new(true), TotalPages: 1,
				ContentType: []string{"CLIENT_DATA"}, ContentKind: "DOCUMENT", TestData: new(false),
			},
		},
		{
			Object: "retained/契約 #+%.txt",
			URL:    "https://storage.googleapis.com/example.test/retained%2F%E5%A5%91%E7%B4%84%20%23%2B%25.txt",
			FindingFile: dlp.FindingFile{
				Sensitivity: new(true), ContentType: []string{"CREDENTIAL", "PII"}, ContentKind: "UNSPECIFIED",
			},
		},
	}
	if diff := cmp.Diff(wantFiles, got.SensitiveObjects); diff != "" {
		t.Errorf("file results mismatch (-want +got):\n%s", diff)
	}
	if got.TotalFiles != len(wantFiles) {
		t.Errorf("total_files = %d, want %d", got.TotalFiles, len(wantFiles))
	}
	if diff := cmp.Diff([]string{"CLIENT_DATA", "CREDENTIAL", "PII"}, got.ContentType); diff != "" {
		t.Errorf("content types mismatch (-want +got):\n%s", diff)
	}

	data, err := json.Marshal(got, json.FormatNilSliceAsNull(true))
	if err != nil {
		t.Fatal(err)
	}
	var output map[string]any
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"findings", "object_scans", "pdf_scans", "total_severity", "severity_reason", "test_data"} {
		if _, exists := output[key]; exists {
			t.Errorf("unexpected field %s", key)
		}
	}
	if strings.Contains(string(data), "legacy@example.test") || strings.Contains(string(data), `"pages"`) {
		t.Error("file summary contains old matches or PDF page details")
	}
	if strings.Contains(string(data), `"sensitivity"`) {
		t.Error("file metadata includes sensitivity")
	}

	decoded, err := parseDLPScanData(`{"dlp_scan":` + string(data) + `}`)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(got, decoded, cmp.AllowUnexported(bucketDLPScan{})); diff != "" {
		t.Errorf("stored dlp_scan mismatch (-want +got):\n%s", diff)
	}

	next := scanDLPTestFiles(t, scanner, "example.test", objects, decoded, started.Add(time.Hour)).withSummary()
	if opens != 1 {
		t.Errorf("opened %d files after unchanged scan, want 1", opens)
	}
	if next.TotalFiles != len(wantFiles) {
		t.Errorf("total_files after unchanged scan = %d, want %d", next.TotalFiles, len(wantFiles))
	}
	if diff := cmp.Diff(wantFiles, next.SensitiveObjects); diff != "" {
		t.Errorf("previous file decisions mismatch (-want +got):\n%s", diff)
	}
}

func TestDLPObjectAccessType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		publicStatus       int
		allowAuthenticated bool
		wantAccessType     string
		wantError          bool
	}{
		{name: "anonymous preferred", allowAuthenticated: true, wantAccessType: allUsers},
		{name: "authenticated grant", publicStatus: http.StatusForbidden, allowAuthenticated: true, wantAccessType: allAuthenticatedUsers},
		{name: "private object", publicStatus: http.StatusForbidden, wantAccessType: allUsers, wantError: true},
		{name: "transient error", publicStatus: http.StatusServiceUnavailable, allowAuthenticated: true, wantAccessType: allUsers, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			object := dlpObject{Open: func(context.Context) (io.ReadCloser, error) {
				if test.publicStatus != 0 {
					return nil, &googleapi.Error{Code: test.publicStatus}
				}
				return io.NopCloser(strings.NewReader("public")), nil
			}}
			if test.allowAuthenticated {
				object.OpenAuthenticated = func(context.Context) (io.ReadCloser, error) {
					if test.wantAccessType != allAuthenticatedUsers {
						t.Error("unexpected authenticated read")
					}
					return io.NopCloser(strings.NewReader("authenticated")), nil
				}
			}
			reader, accessType, err := object.openForDLP(t.Context())
			if reader != nil {
				defer reader.Close()
			}
			if (err != nil) != test.wantError || accessType != test.wantAccessType {
				t.Errorf("access type = %q, err = %v, want %q and error=%t", accessType, err, test.wantAccessType, test.wantError)
			}
		})
	}
}

func TestAuthenticatedFindingURL(t *testing.T) {
	t.Parallel()
	scan := &bucketDLPScan{
		ResourceName: "example",
		SensitiveObjects: []bucketFileScan{{
			Object: "data/顧客.csv", AccessType: allAuthenticatedUsers,
			FindingFile: dlp.FindingFile{Sensitivity: new(true)},
		}},
	}
	file := scan.withSummary().SensitiveObjects[0]
	const want = "https://storage.cloud.google.com/example/data%2F%E9%A1%A7%E5%AE%A2.csv"
	if file.URL != want {
		t.Errorf("URL = %s, want %s", file.URL, want)
	}
	data, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"access_type":"allAuthenticatedUsers"`) {
		t.Error("finding is missing the authenticated access type")
	}
}

func TestAuthenticatedDLPReadRespectsEffectivePublicAccessPrevention(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		body       string
		want       bool
	}{
		{name: "not enforced", statusCode: http.StatusOK, body: `{"booleanPolicy":{}}`, want: true},
		{name: "inherited enforcement", statusCode: http.StatusOK, body: `{"booleanPolicy":{"enforced":true}}`},
		{name: "permission denied", statusCode: http.StatusForbidden, body: `{"error":{"code":403}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			httpClient := &http.Client{Transport: dlpPolicyTestTransport(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/v1/projects/example:getEffectiveOrgPolicy" {
					t.Errorf("unexpected organization policy path %q", req.URL.Path)
				}
				return &http.Response{
					StatusCode: test.statusCode,
					Header:     http.Header{"Content-Type": {"application/json"}},
					Body:       io.NopCloser(strings.NewReader(test.body)),
				}, nil
			})}
			service, err := cloudresourcemanagerv1.NewService(t.Context(), option.WithHTTPClient(httpClient))
			if err != nil {
				t.Fatal(err)
			}
			client := assetClient{orgPolicy: service}
			got, err := client.allowsAuthenticatedDLPRead(t.Context(), "example")
			if got != test.want || (err != nil) != (test.statusCode != http.StatusOK) {
				t.Errorf("authenticated read = %t, error = %v, want %t for HTTP %d", got, err, test.want, test.statusCode)
			}
		})
	}
}

type dlpPolicyTestTransport func(*http.Request) (*http.Response, error)

func (f dlpPolicyTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestFullDLPScanReplacesPreviousResultsOnlyAfterListing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		body       string
		wantOld    bool
	}{
		{
			name:       "successful list removes the previous detection for an excluded object",
			statusCode: http.StatusOK,
			body:       `{"items":[{"name":"old.wav","size":"16","updated":"2023-11-14T22:13:20Z"}]}`,
		},
		{
			name:       "failed list keeps the saved result",
			statusCode: http.StatusForbidden,
			body:       `{"error":{"code":403,"message":"permission denied"}}`,
			wantOld:    true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			httpClient := &http.Client{Transport: dlpPolicyTestTransport(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/storage/v1/b/example-bucket/o" {
					t.Fatalf("unexpected GCS call %s", req.URL)
				}
				return &http.Response{
					StatusCode: test.statusCode,
					Header:     http.Header{"Content-Type": {"application/json"}},
					Body:       io.NopCloser(strings.NewReader(test.body)),
				}, nil
			})}
			gcs, err := storage.NewClient(t.Context(), option.WithHTTPClient(httpClient))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = gcs.Close() })
			client := assetClient{
				gcs:        gcs,
				publicGCS:  gcs,
				dlpScanner: dlp.NewScanner(nil, &dlp.Config{ExcludeFilePatterns: []string{".wav"}}),
			}
			previous := &bucketDLPScan{ResourceName: "example-bucket", ScanTime: 1700000000, SensitiveObjects: []bucketFileScan{{Object: "old.wav"}}}
			got, err := client.dlpScanBucket(t.Context(), "example-bucket", previous, true, allUsers)
			if (err != nil) != test.wantOld || got == nil {
				t.Fatalf("unexpected result: scan=%v err=%v", got, err)
			}
			if (got == previous) != test.wantOld || (!test.wantOld && len(got.SensitiveObjects) != 0) {
				t.Errorf("full scan has %d sensitive objects, want previous=%t", len(got.SensitiveObjects), test.wantOld)
			}
		})
	}
}

func scanDLPTestFiles(t *testing.T, scanner *dlp.Scanner, bucket string, objects []dlpObject, previous *bucketDLPScan, started time.Time) *bucketDLPScan {
	t.Helper()
	list := func(_ context.Context, visit func(dlpObject)) error {
		for _, object := range objects {
			visit(object)
		}
		return nil
	}
	result, err := scanDLPFiles(t.Context(), scanner, bucket, list, previous, started)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
