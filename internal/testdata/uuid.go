package testdata

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

type MockedIDGenerator struct {
	mock.Mock
}

func (mock *MockedIDGenerator) NewUUID() (uuid.UUID, error) {
	args := mock.Called()

	return args.Get(0).(uuid.UUID), args.Error(1)
}
