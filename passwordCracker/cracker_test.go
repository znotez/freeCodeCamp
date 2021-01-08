package passwordCracker

import (
	"fmt"
	"testing"
)

func assertEqual(t *testing.T, actual, expected string) {
	t.Helper()
	if actual != expected {
		t.Errorf("expected %q but get %q", expected, actual)
	}
}

func Test_hash(t *testing.T) {
	tests := []struct {
		name, actual, expected string
	}{
		{"superman", CheckSha1Hash("18c28604dd31094a8d69dae60f1bcd347f1afc5a"), "superman"},
		{"q1w2e3r4t5", CheckSha1Hash("5d70c3d101efd9cc0a69f4df2ddf33b21e641f6a"), "q1w2e3r4t5"},
		{"bubbles1", CheckSha1Hash("b80abc2feeb1e37c66477b0824ac046f9e2e84a0"), "bubbles1"},
		{"01071988", CheckSha1Hash("80540a46a2c1a0eae58d9868f01c32bdcec9a010"), "01071988"},
		{"not found", CheckSha1Hash("03810a46a2c1a0eae58d9332f01c32bdcec9a01a"), "PASSWORD NOT IN DATABASE"},
		{"salt: superman", CheckSha1Hash("53d8b3dc9d39f0184144674e310185e41a87ffd5", true), "superman"},
		{"salt: q1w2e3r4t5", CheckSha1Hash("da5a4e8cf89539e66097acd2f8af128acae2f8ae", true), "q1w2e3r4t5"},
		{"salt: bubbles1", CheckSha1Hash("ea3f62d498e3b98557f9f9cd0d905028b3b019e1", true), "bubbles1"},
		{"salt: 01071988", CheckSha1Hash("05bbf26a28148f531cf57872df546961d1ed0861", true), "01071988"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf(tt.name), func(t *testing.T) {
			assertEqual(t, tt.actual, tt.expected)
		})
	}
}
