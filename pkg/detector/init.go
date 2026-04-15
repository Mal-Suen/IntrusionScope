// Package detector provides threat detection capabilities
// This file contains the detector registry initialization
package detector

// init registers all built-in detectors
func init() {
	registry = NewRegistry()

	registry.Register(NewIOCDetector())
	registry.Register(NewSigmaDetector())
	registry.Register(NewYARADetector())
}

// Global registry instance
var registry *Registry

// GetRegistry returns the global detector registry
func GetRegistry() *Registry {
	return registry
}
