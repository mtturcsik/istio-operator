package v2

// ControlPlaneModeConfig for the mesh
type ControlPlaneModeConfig struct {
	// Type of telemetry implementation to use.
	ControlPlaneModeEnabled bool `json:"enabled,omitempty"`
}
