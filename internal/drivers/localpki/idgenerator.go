package localpki

import "github.com/google/uuid"

// IDGenerator defines a to generate a new google uuid.
type IDGenerator interface {
	NewUUID() (uuid.UUID, error) // TODO verify RFC and link here
}

// IDGeneratorFN is a function type used to passthrough a function to the interface.
// Alias for a function signature.
type IDGeneratorFN func() (uuid.UUID, error)

// NewUUID returns the output of the functions passed within.
// Like the method uuid.NewUUID
func (fn IDGeneratorFN) NewUUID() (uuid.UUID, error) {
	return fn()
}
