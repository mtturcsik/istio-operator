package v2

// ControlPlaneModeConfig for the mesh
type RemoteModeConfig struct {
	// Type of telemetry implementation to use.
	RemoteModeEnabled bool `json:"enabled,omitempty"`
}
