package auth

import (
	"net/http"
	"errors"
	"reflect"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErr    error
	}{
		{
			name:    "valid API key",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
			wantErr: nil,
		},
		{
			name:    "missing Authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "malformed header - no space",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "malformed header - wrong prefix",
			headers: http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "extra spaces but valid format",
			headers: http.Header{"Authorization": []string{"ApiKey my-extra-key"}},
			wantKey: "my-extra-key",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}

			if key != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, key)
			}
		})
	}
}

