package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetApiKey(t *testing.T){
	Tests := map[string]struct{
		input http.Header
		want struct {
			res string
			err error
		}
	}{
		"Correct key": {input: http.Header{"Authorization": []string{"ApiKey dkd"}}, 
			want: struct{
				res string 
				err error
			}{
				res: "dkd",
				err: nil,
			},},
		"No ApiKey prefix": {input: http.Header{"Authorization": []string{"dkd"}}, 
			want: struct{
				res string 
				err error
			}{
				res: "",
				err: errors.New("malformed authorization header"),
			},},
		"Malformed ApiKey prefix": {input: http.Header{"Authorization": []string{"apiKey dkd"}}, 
			want: struct{
				res string 
				err error
			}{
				res: "",
				err: errors.New("malformed authorization header"),
			},},
		"Malformed authorization header": {input: http.Header{"authorization": []string{"ApiKey dkd"}}, 
			want: struct{
				res string 
				err error
			}{
				res: "",
				err: errors.New("no authorization header included"),
			},},
		"No authorization header": {input: http.Header{}, 
			want: struct{
				res string 
				err error
			}{
				res: "",
				err: errors.New("no authorization header included"),
			},},
	}

	for name, tc := range Tests{
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.input)
			if tc.want.err != nil && err == nil {
				t.Fatalf("expected error: %v, got: %v", tc.want.err, err)
			}
			if tc.want.err == nil && err != nil {
				t.Fatalf("expected: %v, got error: %v", tc.want.res, err)
			}
			if tc.want.res != got{
				t.Fatalf("expected: %v, got: %v", tc.want, got)
			}
		})
	}
}