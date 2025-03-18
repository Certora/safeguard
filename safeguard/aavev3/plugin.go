package main

import (
	"log/slog"

	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/safeguard/etherapi"
)

type AaveDetector string

func (a AaveDetector) InvariantChecks(
	statedb *state.StateDB,
	bc etherapi.ChainProxy,
	block *types.Block,
	mr *etherapi.MockRunner,
	allLogs []*types.Log,
) error {
	return invariantChecks(*block.Number(), statedb, mr)
}

func (a AaveDetector) OnPause() {
}

func (a AaveDetector) OnDispose() {
}

func (a AaveDetector) SetLogLevel(l slog.Level) {
	levelVar.Set(l)
}

var Detector AaveDetector
