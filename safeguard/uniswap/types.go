package main

import (
	"log/slog"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

type WithInvariantState interface {
	InvariantState() *InvariantState
	TrackingToken(common.Address) *TokenState
	NotifyNewPool(common.Hash)
}

type TickRangeNative struct {
	tickLower, tickUpper int
}

type PoolState struct {
	key         common.Hash
	currency0   common.Address
	currency1   common.Address
	tickSpacing int
	fee         uint64
	hooks       common.Address

	positionsToRange map[common.Hash]TickRangeNative

	ready bool

	// for solvency monitoring
	monitor0, monitor1, monitorLiquidity bool

	currency0ReqBalance, currency1ReqBalance *uint256.Int
}

type PoolData struct {
	currency0   common.Address
	currency1   common.Address
	tickSpacing int
	fee         uint64
	hooks       common.Address
	key         common.Hash
}

type TokenState struct {
	poolTokens map[common.Hash]bool // true (aka "1") for currency1, false (aka "0") for currency0 (get it?)
	ready      bool

	tokenBalances map[common.Address]bool

	// protocolFees     *uint256.Int
	// transferBalances *uint256.Int
	//owed             *uint256.Int
}

type InvariantState struct {
	poolIdToInfo       map[common.Hash]*PoolState
	tokenAddressToInfo map[common.Address]*TokenState
}

type BlockComputationState struct {
	pc        *PriceComputation
	tickCache map[int]*uint256.Int

	signExtendBit *uint256.Int

	currency0Owed, currency1Owed map[common.Hash]*uint256.Int
}

type TickError struct {
	tickNumber       int
	isGross          bool
	expected, actual string
}

type TickFeeGrowth struct {
	feeGrowthOutside0X128, feeGrowthOutside1X128 *uint256.Int
}

type PoolComputationState struct {
	bc BlockComputationState

	key common.Hash

	liquidityGross, liquidityNet map[int]*uint256.Int

	positionLiquidity, totalPositionLiquidity *uint256.Int

	activePositions uint64

	currTick int

	tickFeeCache map[int]*TickFeeGrowth

	/*
	   scratch slot used for arbitrary slot computations
	*/
	slotComputation *uint256.Int

	/*
	   holds the slot corresponding to the start of the pool state struct
	*/
	poolStateSlot *uint256.Int
	/*
	   holds the slot which contains the tickInfo mapping
	*/
	tickMappingSlot *uint256.Int
	/*
	   holds the slot which contains the positions mapping within the pool
	*/
	positionMappingSlot *uint256.Int

	/*
	   Scratch slot used to compute the location of tick data.
	*/
	tickStateSlot *uint256.Int

	/*
	  field holding the sqrtPriceX96 of the pool
	*/
	sqrtPriceX96 *uint256.Int

	/*
	   cached fields (initially nil) which hold the fee growth global fields of the pool state
	*/
	feeGrowthGlobal0, feeGrowthGlobal1 *uint256.Int
}

type PositionComputationState struct {
	feeGrowthInside0X, feeGrowthInside1X *uint256.Int
	pcs                                  *PoolComputationState
	positionInfoSlot                     common.Hash
	tickRange                            TickRangeNative
	logger                               *slog.Logger
}
