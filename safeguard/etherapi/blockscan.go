package etherapi

import "github.com/ethereum/go-ethereum/core/types"

type BlockScanner interface {
	ScanBlocks(untilBlock uint64, ordered bool, cb func([]*types.Log) error) error
	CurrentBlock() *types.Header
}
