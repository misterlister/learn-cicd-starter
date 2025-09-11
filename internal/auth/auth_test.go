package auth

import (
	"net/http"
	"reflect"
	"testing"
)

func TestAuth(t *testing.T) {
	tests := []struct {
		name    string
		input   http.Header
		want    string
		errWant error
	}{
		{name: "empty header", input: http.Header{}, want: "", errWant: ErrNoAuthHeaderIncluded},
		{name: "lowercase apikey",
			input: http.Header{"Authorization": []string{"apikey test-key-123"}},
			want:  "", errWant: ErrMalformedAuthHeader},
		{name: "no space apikey",
			input: http.Header{"Authorization": []string{"ApiKeytest-key-123"}},
			want:  "", errWant: ErrMalformedAuthHeader},
		{name: "valid apikey",
			input: http.Header{"Authorization": []string{"ApiKey test-key-123"}},
			want:  "test-key-123", errWant: nil},
		{name: "short valid apikey",
			input: http.Header{"Authorization": []string{"ApiKey t1"}},
			want:  "t1", errWant: nil},
		{name: "long valid apikey",
			input: http.Header{"Authorization": []string{"ApiKey this-is-a-long-test-key-123"}},
			want:  "this-is-a-long-test-key-123", errWant: nil},
	}

	for _, tc := range tests {
		got, err := GetAPIKey(tc.input)
		if tc.errWant != err {
			t.Fatalf("%s: expected error: %v, got: %v", tc.name, tc.errWant, err)
		}
		if !reflect.DeepEqual(tc.want, got) {
			t.Fatalf("%s: expected: %v, got: %v", tc.name, tc.want, got)
		}
	}
}
