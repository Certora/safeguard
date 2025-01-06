package main

import (
	"log/slog"
	"math/big"

	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/safeguard/etherapi"
)

type AaveDetector string

func (a AaveDetector) InvariantChecks(
	statedb *state.StateDB,
	bc etherapi.BlockScanner,
	blockNumber big.Int,
	mr *etherapi.MockRunner,
	allLogs []*types.Log,
) error {
	return invariantChecks(blockNumber, statedb, mr)
}

func (a AaveDetector) OnPause() {
}

func (a AaveDetector) OnDispose() {
}

func (a AaveDetector) SetLogLevel(l slog.Level) {
}

var Detector AaveDetector
