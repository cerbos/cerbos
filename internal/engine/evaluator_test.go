package engine

import (
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"reflect"
	"testing"
)

func Test_evaluateCondition(t *testing.T) {
	type args struct {
		condition *runtimev1.Condition
		input     *requestv1.ListResourcesRequest
	}
	tests := []struct {
		name    string
		args    args
		want    *responsev1.ListResourcesResponse_Node
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluateCondition(tt.args.condition, tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("evaluateCondition() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("evaluateCondition() got = %v, want %v", got, tt.want)
			}
		})
	}
}
