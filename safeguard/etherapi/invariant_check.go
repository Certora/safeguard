package etherapi

import (
	"math/big"

	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
)

type InvariantChecker interface {
	InvariantChecks(
		statedb *state.StateDB,
		bc BlockScanner,
		blockNumber big.Int,
		mr *MockRunner,
		allLogs []*types.Log,
	) error

	OnPause()

	OnDispose()

	SetLogLevel(int)
}
