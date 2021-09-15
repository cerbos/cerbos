package util

import "testing"

func TestIsSupportedTestFile(t *testing.T) {
	tests := []struct {
		fileName string
		want bool
	}{
		{"e_test.yml", true},
		{"e_test.yaml", true},
		{"e_test.json", true},
		// Unsupported files
		{"e_test.yl", false},
		{"e_test", false},
		{"e_bar.yaml", false},
	}
	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			if got := IsSupportedTestFile(tt.fileName); got != tt.want {
				t.Errorf("IsSupportedTestFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
