package versions

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestV2_1ChartOrder(t *testing.T) {
	//check the predefined order only, as changes might affect fundamental behaviour
	expectedOrder := [][]string{
		{DiscoveryChart},
		{MeshConfigChart},
		{TelemetryCommonChart, PrometheusChart},
		{RemoteChart},
		{MixerPolicyChart, MixerTelemetryChart, TracingChart, GatewayIngressChart, GatewayEgressChart, GrafanaChart},
		{KialiChart},
		{ThreeScaleChart, WASMExtensionsChart},
	}
	for i := 0; i < len(v2_1ChartOrder); i++ {
		if !cmp.Equal(v2_1ChartOrder[i], expectedOrder[i]) {
			t.Errorf("Incorrect chart order definition at element: %s", v2_1ChartOrder[i])
		}
	}
}
