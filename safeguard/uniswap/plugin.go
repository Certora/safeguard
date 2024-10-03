package main

import (
	"log/slog"
	"math/big"

	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/safeguard/etherapi"
)

type UniswapDetector string

func (u UniswapDetector) InvariantChecks(
	statedb *state.StateDB,
	bc etherapi.BlockScanner,
	blockNumber big.Int,
	mr *etherapi.MockRunner,
	allLogs []*types.Log,
) error {
	return invariantChecks(statedb, bc, blockNumber, mr, allLogs)
}

func (u UniswapDetector) OnPause() {
	safeguardState.Reset()
}

func (u UniswapDetector) OnDispose() {
	// help out the GC?
	safeguardState.Reset()
}

func (u UniswapDetector) SetLogLevel(l slog.Level) {
	levelVar.Set(l)
}

var Detector UniswapDetector
