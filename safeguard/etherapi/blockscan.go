package etherapi

import "github.com/ethereum/go-ethereum/core/types"

/*
Main way that plugins can query into the internal core state (which is
disallowed by virtue of the plugins being in a different package.)

Currently this wraps low-level operations around the BlockChain type, namely getting
the current block header and traversing the chain looking for logs.
*/
type BlockScanner interface {
	/**
	  Starting from the current block (that given by CurrentBlock), traverse the blockchain
	  back until (but excluding) untilBlock. On each block encountered, the logs of that block
	  are passed into the cb. If the cb returns an error, the traversal immediately halts and this function
	  returns an error.

	  The order the block logs can be controlled with the ordered flag. If true, then the logs
	  are passed to cb in "chronological order", i.e., for any two blocks b1 and b2, if b1.blockNumber < b2.blockNumber
	  then b1's logs are passed to cb before b2's logs. This requires a linked list, which
	  increases the memory consumption of this function.

	  If it is false, then the logs are passed to cb in traversal order, i.e., starting from blocks closer to the
	  head of the chain.
	*/
	ScanBlocks(untilBlock uint64, ordered bool, cb func([]*types.Log) error) error
	/*
	   Return the header of the current block, i.e., the head of the block chain *before* the currently processed block
	   is finalized)
	*/
	CurrentBlock() *types.Header
}
