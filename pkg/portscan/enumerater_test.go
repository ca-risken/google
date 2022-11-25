package portscan

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/ca-risken/common/pkg/logging"
	"google.golang.org/api/googleapi"
)

func TestHandleGoogleAPIError(t *testing.T) {
	cases := []struct {
		name    string
		input   error
		wantErr bool
	}{
		{
			name: "No error",
			input: &googleapi.Error{
				Header: http.Header{},
				Code:   403,
				Details: []interface{}{
					map[string]interface{}{
						"@type":  "type.googleapis.com/google.rpc.ErrorInfo",
						"reason": "SERVICE_DISABLED",
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "Error 1",
			input:   errors.New("something error"),
			wantErr: true,
		},
		{
			name: "Error 2",
			input: &googleapi.Error{
				Details: []interface{}{
					1,
					true,
					"test",
				},
			},
			wantErr: true,
		},
		{
			name: "Error 3",
			input: &googleapi.Error{
				Details: []interface{}{
					map[string]interface{}{"unknown": true},
				},
			},
			wantErr: true,
		},
		{
			name: "Error 4",
			input: &googleapi.Error{
				Details: []interface{}{
					map[string]interface{}{"@type": 1},
				},
			},
			wantErr: true,
		},
		{
			name: "Error 5",
			input: &googleapi.Error{
				Details: []interface{}{
					map[string]interface{}{
						"@type":  "unknown",
						"reason": 1,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Error 6",
			input: &googleapi.Error{
				Details: []interface{}{
					map[string]interface{}{
						"@type":  "unknown",
						"reason": "unknown",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Error 7",
			input: &googleapi.Error{
				Details: []interface{}{
					map[string]interface{}{
						"@type":  "type.googleapis.com/google.rpc.ErrorInfo",
						"reason": "unknown",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Error 7",
			input: &googleapi.Error{
				Details: []interface{}{
					map[string]interface{}{
						"@type":  "unknown",
						"reason": "SERVICE_DISABLED",
					},
				},
			},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pc := &PortscanClient{logger: logging.NewLogger()}
			err := pc.handleGoogleAPIError(context.TODO(), c.input)
			if c.wantErr && err == nil {
				t.Errorf("Unexpected no error")
			}
			if !c.wantErr && err != nil {
				t.Errorf("Unexpected error ocurred, err=%+v", err)
			}
		})
	}
}
