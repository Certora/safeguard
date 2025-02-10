package main

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/safeguard/etherapi"
	"github.com/ethereum/go-ethereum/safeguard/logging"
	"github.com/holiman/uint256"
)

func appendUint256Arg(
	buffer []byte,
	v *uint256.Int,
) []byte {
	asArray := v.Bytes32()
	return append(buffer, asArray[:]...)
}

func appendArgs(buffer []byte, args ...*uint256.Int) []byte {
	for _, b := range args {
		buffer = appendUint256Arg(buffer, b)
	}
	return buffer
}

func (bc *BlockComputationState) getSqrtRatioAtTick(tick int) *uint256.Int {
	res, exists := bc.tickCache[tick]
	if exists {
		return res
	}
	d := new(uint256.Int)
	bc.tickCache[tick] = d
	bc.pc.getSqrtRatioAtTick(tick)
	d.Set(bc.pc.ratio)
	return d
}

var levelVar slog.LevelVar
var logger = slog.New(logging.GetHandler(&levelVar))

type storageOffsetsT struct {
	// base slots
	protocolFeesAccruedSlot, balanceOfSlot, poolSlot [32]byte

	// offsets within pool state
	positionsOffset, tickOffset, feeGrowthGlobal0Offset, feeGrowthGlobal1OffsetFrom0, liquidityOffset uint64

	// offsets within tick state
	tickFeeGrowth0Offset, tickFeeGrowth1OffsetFrom0 uint64

	// offsets within position
	feeGrowthInside0Offset, feeGrowthInside1Offset uint64
}

var storageOffsets = storageOffsetsT{
	// all we do is hash these, so it's more convenient in this form
	// we could technically compute this ourselves without going through uint256, but nah
	poolSlot:                uint256.NewInt(6).Bytes32(),
	protocolFeesAccruedSlot: uint256.NewInt(1).Bytes32(),
	balanceOfSlot:           uint256.NewInt(4).Bytes32(),

	positionsOffset:             6,
	tickOffset:                  4,
	feeGrowthGlobal0Offset:      1,
	feeGrowthGlobal1OffsetFrom0: 1,
	liquidityOffset:             3,

	tickFeeGrowth0Offset:      1,
	tickFeeGrowth1OffsetFrom0: 1,

	feeGrowthInside0Offset: 1,
	feeGrowthInside1Offset: 2,
}

func getKeyAs[T any](poolDict map[string]interface{}, key string, err error) (T, error) {
	var ret T
	// monads, but shit
	if err != nil {
		return ret, err
	}
	res, exists := poolDict[key]
	if !exists {
		return ret, fmt.Errorf("Key %s not found", key)
	}
	p, ok := res.(T)
	if !ok {
		return ret, fmt.Errorf("Incorrect type for key %s", key)
	}
	return p, nil
}

func poolDataOfDict(poolDict map[string]interface{}) (PoolData, error) {
	poolKey, err := getKeyAs[string](poolDict, "key", nil)
	spacingFloat, err := getKeyAs[float64](poolDict, "tickSpacing", err)
	feeFloat, err := getKeyAs[float64](poolDict, "tickSpacing", err)
	currency0, err := getKeyAs[string](poolDict, "currency0", err)
	currency1, err := getKeyAs[string](poolDict, "currency1", err)
	hooks, err := getKeyAs[string](poolDict, "hooks", err)
	if err != nil {
		return PoolData{}, err
	}
	key := common.HexToHash(poolKey)
	return PoolData{
		key:         key,
		tickSpacing: int(spacingFloat),
		fee:         uint64(feeFloat),
		currency0:   common.HexToAddress(currency0),
		currency1:   common.HexToAddress(currency1),
		hooks:       common.HexToAddress(hooks),
	}, nil
}

func extractLastBlock(result map[string]interface{}) (uint64, error) {
	lastBlockFloat, err := getKeyAs[float64](result, "lastBlock", nil)
	if err != nil {
		return 0, nil
	}
	return uint64(lastBlockFloat), nil
}

func getPayload(context fmt.Stringer, result map[string]interface{}) (interface{}, error) {
	payloadRaw, exists := result["payload"]
	if !exists {
		return nil, fmt.Errorf("No payload for done result for %s", context)
	}
	return payloadRaw, nil
}

/*
PRE: the token state for tokenAddress is not ready
POST:
 1. if the first component of the return is nil, the token state is still not ready, OTHERWISE
 2. the token state is marked as ready. Further, all pools up to the current block that mention the token are registered in the token state.
    a. For each hash in the first return component, a pool with that ID is registered in the invariant state and is synced until the
    current block. These pools are marked ready.
    b. Further, these pools were NOT registered prior to syncing (they were discovered during block scanning).
    c. Further, each pool id in this list is guaranteed to appear in the token data's poolTokens.
    d. The (p,c1) pairs in the token's tokenPools satisfy invariant 7 of getMonitoredPools below
*/
func (st *InvariantState) loadTokenPools(tokenAddress common.Address, bc etherapi.BlockScanner, currBlock uint64) ([]common.Hash, error) {
	result := make(map[string]interface{})
	err := etherapi.QueryJsonEndpoint(fmt.Sprintf("token-pools/%s", strings.ToLower(tokenAddress.Hex())), &result)
	tokenLogger := logger.With("token", tokenAddress)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch pools for token %s: %s", tokenAddress, err)
	}
	poolPayloadRaw, err := getPayload(tokenAddress, result)
	if err != nil {
		return nil, err
	}
	if poolPayloadRaw == nil {
		return nil, nil
	}
	tokenState := st.tokenAddressToInfo[tokenAddress]
	poolList, ok := poolPayloadRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Invalid type for pool list result")
	}
	for _, pRaw := range poolList {
		p, ok := pRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("Pool data type")
		}
		data, err := poolDataOfDict(p)
		if err != nil {
			return nil, err
		}
		key := data.key
		poolState, exists := st.poolIdToInfo[key]
		poolLogger := tokenLogger.With("pool", key)
		if !exists {
			poolLogger.Info("New pool to monitor")
			poolState, _ = st.addPool(key, data)
		}
		if poolState.currency0 == tokenAddress {
			poolLogger.Info("Monitoring currency 0")
			tokenState.poolTokens[key] = false
			poolState.monitor0 = true
		}
		if poolState.currency1 == tokenAddress {
			poolLogger.Info("Monitoring currency 1")
			tokenState.poolTokens[key] = true
			poolState.monitor1 = true
		}
	}
	lastPoolBlock, err := extractLastBlock(result)
	if err != nil {
		return nil, err
	}
	err = etherapi.QueryJsonEndpoint(fmt.Sprintf("token-transfers/%s", strings.ToLower(tokenAddress.Hex())), &result)
	if err != nil {
		return nil, fmt.Errorf("Could not fetch token transfer info %s", err)
	}
	transferRaw, err := getPayload(tokenAddress, result)
	if err != nil {
		return nil, err
	}
	if transferRaw == nil {
		return nil, nil
	}
	transferList, ok := transferRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Incorrect type for token transfer info")
	}
	for _, addressRaw := range transferList {
		addressString, ok := addressRaw.(string)
		if !ok {
			return nil, fmt.Errorf("Incorrect type for address, expected string")
		}
		addr := common.HexToAddress(addressString)
		tokenState.balanceOfKeys[addr] = true
	}

	lastTransferBlock, err := extractLastBlock(result)
	if err != nil {
		return nil, err
	}
	untilBlock := min(lastTransferBlock, lastPoolBlock)

	extractor := &poolInitScan{
		tokenAddress: tokenAddress,
		st:           st,
		newPools:     make(map[common.Hash]bool),
		tokenState:   tokenState,
	}
	err = bc.ScanBlocks(untilBlock, true, func(l []*types.Log) error {
		return processLogs(l, extractor, MODIFY|INITIALIZE|TRANSFER)
	})
	if err != nil {
		return nil, err
	}
	ret := make([]common.Hash, 0, len(extractor.newPools))
	for p, _ := range extractor.newPools {
		ret = append(ret, p)
	}
	tokenState.ready = true
	return ret, nil
}

func (st *InvariantState) loadPoolAndEnqueue(poolData *PoolState, key common.Hash, bc etherapi.BlockScanner, currBlock uint64, toMonitor *[]common.Hash, fresh *[]common.Hash) error {
	poolLogger := logger.With("pool", key)
	if !poolData.ready {
		hasPositions, err := st.loadInitialPositions(key, bc, currBlock)
		if err != nil {
			poolLogger.Warn("Error loading initial positions, trying again later", "err", err)
			return err
		}
		if hasPositions {
			poolData.ready = true
			*fresh = append(*fresh, key)
		}
	}
	if poolData.ready {
		*toMonitor = append(*toMonitor, key)
	} else {
		poolLogger.Info("Initial data not ready yet, trying again later", "key", key.Hex())
	}
	return nil
}

type FatalError struct {
	msg string
}

func (s FatalError) Error() string {
	return s.msg
}

func Fatal(s string) FatalError {
	return FatalError{
		msg: s,
	}
}

/*
POST STATE INVARIANTS:
 1. All pool keys that appear in the first list of the return value exist in the invariant state PoolIdToInfo
 2. All such pool keys are marked as "ready"
 3. All pool keys that appear in the second list have at least one entry in the first list (and thus are also ready)
 4. All pool keys in the second list were not ready before this call (because they were not loaded or not known about)
 5. All ready pools have their positions synced until the most recent block (excluding current blocks logs)
 6. All ready tokens have their pool lists synced until the most recent block (excluding current block logs)
    a. NB: it is not guaranteed that all such pools are actually ready
 7. For all tuples (p,c1) in a ready token t's tokenPool:
    a. p is registered with the pool states
    b. if c1 is true, then p's monitor1 field is true, and p's currency1 field is equal to t
    c. if c1 is false, then p's monitor0 field is true, and p's currency0 field is equal to t
*/
func (st *InvariantState) getMonitoredPools(bc etherapi.BlockScanner, currBlock uint64) ([]common.Hash, []common.Hash, error) {
	var tokenItems []interface{}
	err := etherapi.QueryJsonEndpoint("token-targets", &tokenItems)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get token targets %s", err)
	}

	toRet := []common.Hash{}
	freshPools := []common.Hash{}

	/*
	  Holds the list of all pools that we want to monitor, which may or may not be ready yet
	*/
	var allPools = make([]*PoolState, 0, len(st.poolIdToInfo))

	for _, p := range tokenItems {
		tokenAddress, ok := p.(string)
		if !ok {
			return nil, nil, fmt.Errorf("Token items was not of correct type")
		}
		if err != nil {
			return nil, nil, err
		}
		tokenLogger := logger.With("token", tokenAddress)
		tokenId := common.HexToAddress(tokenAddress)
		tokenData, exists := st.tokenAddressToInfo[tokenId]
		if !exists {
			tokenLogger.Info("Got new request to monitor token")
			tokenData = &TokenState{
				poolTokens:      make(map[common.Hash]bool),
				ready:           false,
				balanceOfKeys:   make(map[common.Address]bool),
				poolBalanceOwed: new(uint256.Int),
				poolBalances:    make(map[common.Hash]*uint256.Int),
			}
			st.tokenAddressToInfo[tokenId] = tokenData
		}
		if !tokenData.ready {
			fresh, err := st.loadTokenPools(tokenId, bc, currBlock)
			if err != nil {
				return nil, nil, err
			}
			if fresh != nil {
				// the invariant of loadTokenPool says that fresh is non-null IFF tokenData is ready
				if !tokenData.ready {
					tokenLogger.Error("Invariant broken, have fresh state, but token is not ready")
					return nil, nil, Fatal("Invariant broken")
				}
				// all pools that we found while loading the set of pools for this token
				// are necessarily fresh, even if we don't see their ready status change below
				// NB: all pool ids mentioned here are definitely added to the token's pools,
				// so these pools do NOT need to be added to the allPools list
				freshPools = append(freshPools, fresh...)
			}
		}
		/*
		 if the token is ready, then all pools for that token are known, and should be loaded.
		*/
		if tokenData.ready {
			for p, _ := range tokenData.poolTokens {
				pd := st.poolIdToInfo[p]
				allPools = append(allPools, pd)
			}
		}
	}

	var poolItems []interface{}
	err = etherapi.QueryJsonEndpoint("pool-targets", &poolItems)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get pool targets %s", err)
	}
	for _, p := range poolItems {
		poolDict, ok := p.(map[string]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("Pool targets was not of correct type")
		}
		poolKey, err := getKeyAs[string](poolDict, "key", nil)
		if err != nil {
			return nil, nil, err
		}
		key := common.HexToHash(poolKey)
		poolState, exists := st.poolIdToInfo[key]
		if !exists {
			logger.Info("New request to monitor pool", "pool", poolKey)
			data, err := poolDataOfDict(poolDict)
			if err != nil {
				return nil, nil, err
			}
			poolState, _ = st.addPool(
				key,
				data,
			)

		}
		allPools = append(allPools, poolState)
	}
	/*
	  NB: some pools may be in this list multiple times (it is monitored explicitly *and* we are monitoring it for one or two involved tokens)
	  This is basically fine, all we're saving is some web-requests, which on the server side are very fast to serve if the data isn't ready.
	  If one of the items in this list switches the pool state from not ready to ready, then later entries with the same pool will just add the
	  same pool to the toRet list.

	  This is also fine, because all we do with this list is iterate over it and populate a map.
	  Since it all comes down to a map anyway, the duplication has such little overhead I'm not willing to spend the memory to de-dup
	*/

	/*
	  INVARIANT: allPools now holds a pointer to all pools that we are interested in monitoring. These pools may or may not be ready.
	*/
	for _, poolState := range allPools {
		key := poolState.key
		poolLogger := logger.With("pool", key)
		if !poolState.ready {
			hasPositions, err := st.loadInitialPositions(key, bc, currBlock)
			if err != nil {
				poolLogger.Warn("Error loading initial positions, trying again later", "err", err)
			}
			/*
			 if we are switching from not ready to ready, then add this pool to freshPools, indicating all data needs to be loaded
			*/
			if hasPositions {
				poolState.ready = true
				freshPools = append(freshPools, key)
			}
		}
		/*
		  If the pool is ready, add it toRet
		*/
		if poolState.ready {
			toRet = append(toRet, key)
		} else {
			poolLogger.Info("Initial data is not ready yet, trying later")
		}
	}
	return toRet, freshPools, nil
}

func (st *InvariantState) Reset() {
	st.poolIdToInfo = map[common.Hash]*PoolState{}
	st.tokenAddressToInfo = map[common.Address]*TokenState{}
}

func (st *InvariantState) ResetPool(pool common.Hash) {
	currState := st.poolIdToInfo[pool]
	// TODO: tell the tokens about this somehow
	if currState.monitor0 {
		// clear the token state?
	}
	delete(st.poolIdToInfo, pool)
}

func (st *InvariantState) addPool(poolKey common.Hash, data PoolData) (*PoolState, bool) {
	toRet, exists := st.poolIdToInfo[poolKey]
	if exists {
		return toRet, false
	}
	toRet = &PoolState{
		currency0:        data.currency0,
		currency1:        data.currency1,
		tickSpacing:      data.tickSpacing,
		fee:              data.fee,
		hooks:            data.hooks,
		positionsToRange: map[common.Hash]TickRangeNative{},
		ready:            false,
		key:              poolKey,
	}
	st.poolIdToInfo[poolKey] = toRet
	return toRet, true
}

/*
PRE: the pool with key pool is not ready
POST:
 1. if this function returns false, then the pool is not ready
 2. otherwise, the pool is marked as ready, and all positions for the pool up until the current block (but excluding the most recent logs) have been registered.
*/
func (st *InvariantState) loadInitialPositions(pool common.Hash, bc etherapi.BlockScanner, currBlock uint64) (bool, error) {
	start := time.Now()
	root := map[string]interface{}{}

	err := etherapi.QueryJsonEndpoint(fmt.Sprintf("pool-positions/%s", strings.ToLower(pool.Hex())), &root)
	payload, err := getPayload(pool, root)
	if err != nil {
		return false, err
	}
	lastJsonBlock, err := extractLastBlock(root)
	if err != nil {
		return false, err
	}

	positionList, ok := payload.([]interface{})
	if !ok {
		return false, fmt.Errorf("payload was not a list")
	}
	pi := st.poolIdToInfo[pool]
	for _, p := range positionList {
		m, ok := p.(map[string]interface{})
		if !ok {
			return false, fmt.Errorf("Position information was not a dictionary")
		}
		positionBytes, err := getKeyAs[string](m, "positionHash", nil)
		if err != nil {
			return false, err
		}

		hash := common.HexToHash(positionBytes)
		_, exists := pi.positionsToRange[hash]
		if exists {
			continue
		}
		lowerTickFloat, err := getKeyAs[float64](m, "tickLower", nil)
		upperTickFloat, err := getKeyAs[float64](m, "tickUpper", err)
		if err != nil {
			return false, err
		}
		upperTick := int(upperTickFloat)
		lowerTick := int(lowerTickFloat)
		pi.positionsToRange[hash] = TickRangeNative{tickLower: lowerTick, tickUpper: upperTick}
	}
	scanner := &positionExtractor{
		inv:  st,
		pool: pool,
	}
	poolLogger := logger.With("pool", pool)
	poolLogger.Info("Loaded positions from server")
	if lastJsonBlock != 0 {
		bc.ScanBlocks(lastJsonBlock, false, func(logs []*types.Log) error {
			return processLogs(logs, scanner, MODIFY)
		})
	}
	poolLogger.Debug("Initial load of positions done", "time", time.Since(start))
	return true, nil
}

func getNativeRange(start, end int) *TickRangeNative {
	return &TickRangeNative{
		tickLower: start,
		tickUpper: end,
	}
}

func init() {
	safeguardState.poolIdToInfo = make(map[common.Hash]*PoolState)
	safeguardState.tokenAddressToInfo = make(map[common.Address]*TokenState)
	initPC()
}

var safeguardState InvariantState

var poolManagerAddress = common.HexToAddress("0x000000000004444c5dc75cB358380D2e3dE08A90")

var transferTopic = common.HexToHash("0x1b3d7edb2e9c0b0e7c525b20aaaef0f5940d2ed71663c7d39266ecafac728859")
var swapTopic = common.HexToHash("0x40e9cecb9f5f1f1c5b9c97dec2917b7ee92e57ba5563708daca94dd84ad7112f")
var modifyLiquidityTopic = common.HexToHash("0xf208f4912782fd25c7f114ca3723a2d5dd6f3bcc3ac8db5af63baa85f711d5ec")
var initializeTopic = common.HexToHash("0xdd466e674ea557f56295e2d0218a125ea4b4f0f6f3307b95f85e6110838d6438")

func (ps *PoolState) AddPosition(
	positionKey common.Hash,
	tickLower, tickUpper int,
) {
	r := TickRangeNative{
		tickLower: tickLower,
		tickUpper: tickUpper,
	}
	ps.positionsToRange[positionKey] = r
}

func (st *InvariantState) AddPosition(
	poolId, position common.Hash,
	tickLower, tickUpper int,
) {
	pool, _ := st.poolIdToInfo[poolId]
	pool.AddPosition(position, tickLower, tickUpper)
}

func convert24BitToInt(value uint64) int {
	// Mask to get only the lowest 24 bits
	const mask uint64 = 0xFFFFFF
	// Extract the 24-bit value
	ext24BitValue := value & mask

	// Check if the 24th bit (sign bit) is set
	if ext24BitValue&0x800000 != 0 {
		// Negative number: sign-extend to a 64-bit int
		return int(ext24BitValue | ^mask)
	}
	// Positive number: directly convert to int
	return int(ext24BitValue)
}

func extractBigEndianUint24(b []byte, start int) uint64 {
	return uint64(b[start])<<16 | uint64(b[start+1])<<8 | uint64(b[start+2])
}

func abiToNativeTick(b []byte, start int) int {
	return convert24BitToInt(extractBigEndianUint24(b, start))
}

const poolUpdateEndpoint = "pools"
const tokenUpdateEndpoint = "tokens"

/*
MODIFIES: tickStateSlot
*/
func (pcs *PoolComputationState) slotForTickState(
	tick int,
) {
	tickAsUint := uint64(tick) // gives the twos complement
	pcs.tickStateSlot.SetUint64(tickAsUint)
	pcs.bc.signExtendBit.SetUint64(7)
	pcs.tickStateSlot.ExtendSign(pcs.tickStateSlot, pcs.bc.signExtendBit)
	m := pcs.tickMappingSlot.Bytes32()
	tickBytes := pcs.tickStateSlot.Bytes32()

	hashResult := crypto.Keccak256Hash(tickBytes[:], m[:])
	pcs.tickStateSlot.SetBytes(hashResult[:])
}

/*
MODIFIES: tickStateSlot
*/
func (pcs *PoolComputationState) loadTickFees(db *state.StateDB, tick int) *TickFeeGrowth {
	var ret *TickFeeGrowth
	var exists bool
	if ret, exists = pcs.tickFeeCache[tick]; !exists {
		// pcs.tickStateSlot is now point to the beginning of the relevant TickInfo
		pcs.slotForTickState(tick)
		pcs.tickStateSlot.AddUint64(pcs.tickStateSlot, storageOffsets.tickFeeGrowth0Offset) // pointing now to feegrowth0
		feeGrowth0 := new(uint256.Int)
		rawRead := db.GetState(poolManagerAddress, pcs.tickStateSlot.Bytes32())
		feeGrowth0.SetBytes(rawRead[:])
		pcs.tickStateSlot.AddUint64(pcs.tickStateSlot, storageOffsets.tickFeeGrowth1OffsetFrom0) // pointing now to feegrowth1
		rawRead = db.GetState(poolManagerAddress, pcs.tickStateSlot.Bytes32())
		feeGrowth1 := new(uint256.Int)
		feeGrowth1.SetBytes(rawRead[:])
		ret = &TickFeeGrowth{
			feeGrowthOutside0X128: feeGrowth0,
			feeGrowthOutside1X128: feeGrowth1,
		}
		pcs.tickFeeCache[tick] = ret
	}
	return ret
}

/*
MODIFIES: slotComputation, feeGrowthGlobal1, feeGrowthGlobal0
*/
func (pcs *PoolComputationState) loadGlobalFees(db *state.StateDB) error {
	if pcs.feeGrowthGlobal0 != nil {
		return nil
	}
	if pcs.feeGrowthGlobal1 != nil {
		return Fatal("invariant broken")
	}
	pcs.slotComputation.Set(pcs.poolStateSlot)

	pcs.slotComputation.AddUint64(pcs.slotComputation, storageOffsets.feeGrowthGlobal0Offset) // points now at feegrowthglobal
	raw := db.GetState(poolManagerAddress, pcs.slotComputation.Bytes32())

	pcs.feeGrowthGlobal0 = new(uint256.Int)
	pcs.feeGrowthGlobal0.SetBytes(raw[:])

	pcs.slotComputation.AddUint64(pcs.slotComputation, storageOffsets.feeGrowthGlobal1OffsetFrom0)

	raw = db.GetState(poolManagerAddress, pcs.slotComputation.Bytes32())

	pcs.feeGrowthGlobal1 = new(uint256.Int)
	pcs.feeGrowthGlobal1.SetBytes(raw[:])
	return nil
}

/*
MODIFIES: pcs.slotComputation
*/
func (pcs *PoolComputationState) feeGrowthInside(
	db *state.StateDB,
	currTick, positionLower, positionUpper int,
) (*uint256.Int, *uint256.Int) {
	positionLowerFees := pcs.loadTickFees(db, positionLower)
	positionUpperFees := pcs.loadTickFees(db, positionUpper)
	feeGrowthInside0X128 := new(uint256.Int)
	feeGrowthInside1X128 := new(uint256.Int)
	if currTick < positionLower {
		feeGrowthInside0X128.Sub(positionLowerFees.feeGrowthOutside0X128, positionUpperFees.feeGrowthOutside0X128)
		feeGrowthInside1X128.Sub(positionLowerFees.feeGrowthOutside1X128, positionUpperFees.feeGrowthOutside1X128)
	} else if currTick >= positionUpper {
		feeGrowthInside0X128.Sub(positionUpperFees.feeGrowthOutside0X128, positionLowerFees.feeGrowthOutside0X128)
		feeGrowthInside1X128.Sub(positionUpperFees.feeGrowthOutside1X128, positionLowerFees.feeGrowthOutside1X128)
	} else {
		pcs.loadGlobalFees(db)
		feeGrowthInside0X128.Sub(pcs.feeGrowthGlobal0, positionLowerFees.feeGrowthOutside0X128)
		feeGrowthInside0X128.Sub(feeGrowthInside0X128, positionUpperFees.feeGrowthOutside0X128)

		feeGrowthInside1X128.Sub(pcs.feeGrowthGlobal1, positionLowerFees.feeGrowthOutside1X128)
		feeGrowthInside1X128.Sub(feeGrowthInside1X128, positionUpperFees.feeGrowthOutside1X128)
	}
	return feeGrowthInside0X128, feeGrowthInside1X128
}

func getTickSumIn(m map[int]*uint256.Int, tick int) *uint256.Int {
	var toRet *uint256.Int
	var exists bool
	if toRet, exists = m[tick]; !exists {
		toRet = new(uint256.Int)
		m[tick] = toRet
	}
	return toRet
}

func (pcs *PoolComputationState) getGrossTickSum(tick int) *uint256.Int {
	return getTickSumIn(pcs.liquidityGross, tick)
}

func (pcs *PoolComputationState) getNetTickSum(tick int) *uint256.Int {
	return getTickSumIn(pcs.liquidityNet, tick)
}

func (pcs *PoolComputationState) addToCurrency1(amt *uint256.Int) {
	pcs.currency1Owed.Add(pcs.currency1Owed, amt)
}

func (pcs *PoolComputationState) addToCurrency0(amt *uint256.Int) {
	pcs.currency0Owed.Add(pcs.currency0Owed, amt)
}

func (pos *PositionComputationState) getFeeGrowthInside(statedb *state.StateDB) (*uint256.Int, *uint256.Int) {
	if pos.feeGrowthInside0X == nil {
		feeGrowthInside0X, feeGrowthInside1X := pos.pcs.feeGrowthInside(statedb, pos.pcs.currTick, pos.tickRange.tickLower, pos.tickRange.tickUpper)
		pos.feeGrowthInside0X = feeGrowthInside0X
		pos.feeGrowthInside1X = feeGrowthInside1X
	}
	return pos.feeGrowthInside0X, pos.feeGrowthInside1X
}

func (pos *PositionComputationState) computeFees(statedb *state.StateDB, inside0 bool) *uint256.Int {
	pos.pcs.slotComputation.SetBytes(pos.positionInfoSlot[:])
	var offsetAmount uint64
	if inside0 {
		offsetAmount = storageOffsets.feeGrowthInside0Offset
	} else {
		offsetAmount = storageOffsets.feeGrowthInside1Offset
	}
	pos.pcs.slotComputation.AddUint64(pos.pcs.slotComputation, offsetAmount)
	feeGrowthInsideKLastRaw := statedb.GetState(poolManagerAddress, pos.pcs.slotComputation.Bytes32())
	feeGrowthInsideLastKUint := new(uint256.Int)
	feeGrowthInsideLastKUint.SetBytes(feeGrowthInsideKLastRaw[:])
	feeGrowthInside0X, feeGrowthInside1X := pos.getFeeGrowthInside(statedb)

	pos.logger.Debug("Fee computation parameters",
		"feeGrowthInsideValue", feeGrowthInsideLastKUint,
		"feeGrowthInside0X", feeGrowthInside0X,
		"feeGrowthInside1X", feeGrowthInside1X,
		"positionLiquidity", pos.pcs.positionLiquidity,
		"tickLower", pos.tickRange.tickLower,
		"tickUpper", pos.tickRange.tickUpper,
		"is currency0?", inside0,
	)
	var feeGrowthToSubtractFrom *uint256.Int
	if inside0 {
		feeGrowthToSubtractFrom = feeGrowthInside0X
	} else {
		feeGrowthToSubtractFrom = feeGrowthInside1X
	}
	feeGrowthInsideLastKUint.Sub(feeGrowthToSubtractFrom, feeGrowthInsideLastKUint)
	pos.pcs.bc.pc.mulDiv(feeGrowthInsideLastKUint, pos.pcs.positionLiquidity, pos.pcs.bc.pc.namedConstant.Q128, feeGrowthInsideLastKUint)
	if inside0 {
		pos.pcs.addToCurrency0(feeGrowthInsideLastKUint)
	} else {
		pos.pcs.addToCurrency1(feeGrowthInsideLastKUint)
	}
	pos.logger.Debug("Fee result", "result", feeGrowthInsideLastKUint)
	return feeGrowthInsideLastKUint
}

func (pos *PositionComputationState) processPosition(
	poolState *PoolState,
	statedb *state.StateDB,
) error {
	positionLogger := pos.logger
	pcs := pos.pcs
	positionLogger.Debug("Position state", "liquidity slot", pos.positionInfoSlot)
	raw := statedb.GetState(poolManagerAddress, pos.positionInfoSlot)
	pcs.positionLiquidity.SetBytes(raw.Bytes())
	positionLogger.Debug("Position state", "liquidity", pcs.positionLiquidity)
	tickRange := pos.tickRange
	currTick := pos.pcs.currTick
	if tickRange.tickLower <= currTick && currTick < tickRange.tickUpper {
		pcs.activePositions++
		pcs.totalPositionLiquidity = pcs.totalPositionLiquidity.Add(pcs.totalPositionLiquidity, pcs.positionLiquidity)
	}
	grossLower := pcs.getGrossTickSum(tickRange.tickLower)
	grossLower.Add(grossLower, pcs.positionLiquidity)
	grossUpper := pcs.getGrossTickSum(tickRange.tickUpper)
	grossUpper.Add(grossUpper, pcs.positionLiquidity)

	netLower := pcs.getNetTickSum(tickRange.tickLower)
	netLower.Add(netLower, pcs.positionLiquidity)
	netUpper := pcs.getNetTickSum(tickRange.tickUpper)
	netUpper.Sub(netUpper, pcs.positionLiquidity)

	positionLogger.Debug("> start fee computation")
	if poolState.monitor0 {
		positionLogger.Debug(">> Start token balance computation", "token", poolState.currency0)
		scratchUint := pos.computeFees(statedb, true)

		// now let's compute how much is owed for this position
		tickLowerPrice := pcs.bc.getSqrtRatioAtTick(tickRange.tickLower)
		tickUpperPrice := pcs.bc.getSqrtRatioAtTick(tickRange.tickUpper)

		positionLogger.Debug(">> Price parameters",
			"token", poolState.currency0,
			"tickLowerPrice", tickLowerPrice,
			"tickUpperPrice", tickUpperPrice,
			"sqrtPriceX96", pcs.sqrtPriceX96,
			"liquidity", pcs.positionLiquidity,
			"tickLower", tickRange.tickLower,
			"tickUpper", tickRange.tickUpper,
		)

		pc := pcs.bc.pc
		if tickLowerPrice.Gt(pcs.sqrtPriceX96) {
			pc.sqrtRatioAX96.Set(tickLowerPrice)
		} else {
			pc.sqrtRatioAX96.Set(pcs.sqrtPriceX96)
		}
		if tickUpperPrice.Gt(pcs.sqrtPriceX96) {
			pc.sqrtRatioBX96.Set(tickUpperPrice)
		} else {
			pc.sqrtRatioBX96.Set(pcs.sqrtPriceX96)
		}
		pc.getAmount0DeltaRoundDown(pcs.positionLiquidity, scratchUint)
		positionLogger.Debug("<< Balance computation finished", "result", scratchUint)
		pcs.addToCurrency0(scratchUint)
	}
	if poolState.monitor1 {
		positionLogger.Debug(">> Start token balance computation", "token", poolState.currency1)
		pcs.slotComputation.SetBytes(pos.positionInfoSlot[:])
		pcs.slotComputation.AddUint64(pcs.slotComputation, storageOffsets.feeGrowthInside1Offset)

		scratchUint := pos.computeFees(statedb, false)

		tickLowerPrice := pcs.bc.getSqrtRatioAtTick(tickRange.tickLower)
		tickUpperPrice := pcs.bc.getSqrtRatioAtTick(tickRange.tickUpper)

		positionLogger.Debug(">> Price parameters",
			"token", poolState.currency1,
			"tickLowerPrice", tickLowerPrice,
			"tickUpperPrice", tickUpperPrice,
			"sqrtPriceX96", pcs.sqrtPriceX96,
			"liquidity", pcs.positionLiquidity,
			"tickLower", tickRange.tickLower,
			"tickUpper", tickRange.tickUpper,
		)

		pc := pcs.bc.pc
		if tickLowerPrice.Lt(pcs.sqrtPriceX96) {
			pc.sqrtRatioAX96.Set(tickLowerPrice)
		} else {
			pc.sqrtRatioAX96.Set(pcs.sqrtPriceX96)
		}
		if tickUpperPrice.Lt(pcs.sqrtPriceX96) {
			pc.sqrtRatioBX96.Set(tickUpperPrice)
		} else {
			pc.sqrtRatioBX96.Set(pcs.sqrtPriceX96)
		}
		pc.getAmount1DeltaRoundDown(pcs.positionLiquidity, scratchUint)
		pcs.addToCurrency1(scratchUint)
		positionLogger.Debug("<< Balance computation finished", "result", scratchUint)
		// phew
	}
	positionLogger.Debug("< end fee computation")
	return nil
}

func (pcs *PoolComputationState) processPool(
	statedb *state.StateDB,
) error {
	pool := pcs.key
	poolLogger := logger.With("pool", pool)
	poolState := safeguardState.poolIdToInfo[pool]
	poolLogger.Debug("Working on pool", "monitor0", poolState.monitor0, "monitor1", poolState.monitor1)
	if !poolState.ready {
		poolLogger.Error("Trying to do work on an incomplete pool, this is bad!")
		return Fatal("Invariant broken")
	}
	poolDataSlot := crypto.Keccak256Hash(pool[:], storageOffsets.poolSlot[:])
	// get current tick
	slot0value := statedb.GetState(poolManagerAddress, common.Hash(poolDataSlot))

	pcs.poolStateSlot.SetBytes(poolDataSlot[:])
	poolLogger.Debug("Trying to access state", "slot", pcs.poolStateSlot)

	pcs.currTick = convert24BitToInt(extractBigEndianUint24(slot0value[:], 9))
	poolLogger.Debug("Pool state", "tick", pcs.currTick)
	pcs.sqrtPriceX96.SetBytes(slot0value[12:32])

	if poolState.monitor0 {
		pcs.currency0Owed = new(uint256.Int)
	}
	if poolState.monitor1 {
		pcs.currency1Owed = new(uint256.Int)
	}

	pcs.positionMappingSlot.AddUint64(pcs.poolStateSlot, storageOffsets.positionsOffset)
	pcs.tickMappingSlot.AddUint64(pcs.poolStateSlot, storageOffsets.tickOffset)
	positionMappingSlotRaw := pcs.positionMappingSlot.Bytes32()
	poolLogger.Debug("Pool state", "position slot", common.Hash(positionMappingSlotRaw))

	poolLogger.Debug("Pool state", "num positions", len(poolState.positionsToRange))
	// start position sums
	for pos, tickRange := range poolState.positionsToRange {
		positionLogger := poolLogger.With("position", pos)
		positionInfoSlot := crypto.Keccak256Hash(pos.Bytes(), positionMappingSlotRaw[:])
		positionState := PositionComputationState{
			pcs:               pcs,
			feeGrowthInside0X: nil,
			feeGrowthInside1X: nil,
			positionInfoSlot:  positionInfoSlot,
			tickRange:         tickRange,
			logger:            positionLogger,
		}
		positionState.processPosition(poolState, statedb)
	}
	if poolState.monitor0 {
		ts, exists := safeguardState.tokenAddressToInfo[poolState.currency0]
		if !exists {
			return Fatal(fmt.Sprintf("Expected to find token state for %s, didn't exist", poolState.currency0))
		}
		ts.reportPoolBalance(pool, pcs.currency0Owed)
	}
	if poolState.monitor1 {
		ts, exists := safeguardState.tokenAddressToInfo[poolState.currency1]
		if !exists {
			return Fatal(fmt.Sprintf("Expected to find token state for monitored token %s, didn't exist", poolState.currency1))
		}
		ts.reportPoolBalance(pool, pcs.currency1Owed)
	}
	return nil
}

var addressZeroPadding [12]byte

func invariantChecks(
	statedb *state.StateDB,
	bc etherapi.BlockScanner,
	blockNumber big.Int,
	mr *etherapi.MockRunner,
	allLogs []*types.Log,
) error {
	err := invariantChecksInner(statedb, bc, blockNumber, mr, allLogs)
	if err != nil {
		safeguardState.Reset()
	}
	return err
}

func (t *TokenState) reportPoolBalance(pool common.Hash, amount *uint256.Int) error {
	curr, exists := t.poolBalances[pool]
	if !exists {
		curr = new(uint256.Int)
		t.poolBalances[pool] = curr
	}
	// first time seeing this pool, or first time computation (the effect is the same)
	if !exists {
		curr.Set(amount)
		t.poolBalanceOwed.Add(t.poolBalanceOwed, amount)
		return nil
	}
	// no net change
	if amount.Eq(curr) {
		return nil

		// balance decrease, compute the absolute difference and subtract
		// amount < curr
	} else if amount.Lt(curr) {
		diff := new(uint256.Int)
		// diff = curr - amount
		diff.Sub(curr, amount)
		// balance = balance - (curr - amount)
		t.poolBalanceOwed.Sub(t.poolBalanceOwed, diff)
	} else {
		// amount is increasing
		diff := new(uint256.Int)
		diff.Sub(amount, curr)
		t.poolBalanceOwed.Add(t.poolBalanceOwed, diff)
	}
	curr.Set(amount)
	return nil
}

type TokenResult string
type PoolResult string

type CheckResultSwitch interface {
	Key() string
}

func (t TokenResult) Key() string {
	return "address"
}

func (p PoolResult) Key() string {
	return "id"
}

func getInvariantResult[T CheckResultSwitch](blockNumber big.Int, id string, holds bool, cond map[string]interface{}, others ...map[string]interface{}) map[string]interface{} {
	var impl T
	var statusString string
	if holds {
		statusString = "success"
	} else {
		statusString = "failure"
	}
	std := map[string]interface{}{
		"invariantStatus":      statusString,
		"blockNumber":          blockNumber.Uint64(),
		"calculationTimestamp": time.Now().Unix(),
		"conditionsChecked":    append([]map[string]interface{}{cond}, others...),
	}
	std[impl.Key()] = strings.ToLower(id)
	return std
}

func getConditionResult(name string, status bool, values ...any) map[string]interface{} {
	vDict := make(map[string]interface{})
	var currKey string
	for i, r := range values {
		if i%2 == 0 {
			k, ok := r.(string)
			if !ok {
				currKey = fmt.Sprintf("BADKEY!%d", i)
			} else {
				currKey = k
			}
		} else {
			switch v := r.(type) {
			case int:
				vDict[currKey] = v
			case string:
				vDict[currKey] = v
			case bool:
				vDict[currKey] = v
			case uint64:
				vDict[currKey] = v
			default:
				vDict[currKey] = fmt.Sprintf("BADVALUE!%d", i)
			}
		}
	}
	if len(values)%2 == 1 {
		vDict[currKey] = "!MISSING"
	}
	return map[string]interface{}{
		"condition": name,
		"status":    status,
		"values":    vDict,
	}
}

func invariantChecksInner(
	statedb *state.StateDB,
	bc etherapi.BlockScanner,
	blockNumber big.Int,
	mr *etherapi.MockRunner,
	allLogs []*types.Log,
) error {
	start := time.Now()
	if safeguardState.poolIdToInfo == nil {
		safeguardState.poolIdToInfo = make(map[common.Hash]*PoolState)
		safeguardState.tokenAddressToInfo = make(map[common.Address]*TokenState)
	}
	poolsToMonitor, fresh, err := safeguardState.getMonitoredPools(bc, blockNumber.Uint64())
	if err != nil {
		logger.Error("Monitoring task loading failed, clearing all statuses", "err", err)
		return err
	}
	poolsNeedWork := make(map[common.Hash]bool)
	for _, p := range poolsToMonitor {
		poolsNeedWork[p] = false
	}
	/*
	 force a check for all pools that were newly loaded, we know that all such pools must exist in needsWork, by the invariant on getMonitoredPools
	*/
	for _, p := range fresh {
		poolsNeedWork[p] = true
	}
	/*
	   All tokens and pools are synced up until the most recent block's logs
	   ingest the most recent logs, adding positions and pools if necessary.
	*/
	err = processLogs(allLogs, &logMultiExtractor{
		inv:             &safeguardState,
		poolsNeedsCheck: poolsNeedWork,
	}, MODIFY|SWAP|INITIALIZE|TRANSFER)
	if err != nil {
		return err
	}
	perCheckState := BlockComputationState{
		pc:            getPC(),
		tickCache:     make(map[int]*uint256.Int),
		signExtendBit: new(uint256.Int),
	}
	/*
	   Find those tokens which do not have a running sum yet.
	   Force all involved pools to recompute
	*/
	for _, tokenState := range safeguardState.tokenAddressToInfo {
		if !tokenState.ready {
			continue
		}
		for p, _ := range tokenState.poolTokens {
			pState := safeguardState.poolIdToInfo[p]
			if !pState.ready {
				continue
			}
			if _, exists := tokenState.poolBalances[p]; !exists {
				poolsNeedWork[p] = true
			}
		}
	}
	// start pool computation
	for pool, doCheck := range poolsNeedWork {
		poolLogger := logger.With("pool", pool)
		// TODO: send a "no changes" message to the server
		if !doCheck {
			poolLogger.Debug("No work needed")
			continue
		}
		pcs := &PoolComputationState{
			bc:                  perCheckState,
			tickFeeCache:        map[int]*TickFeeGrowth{},
			slotComputation:     new(uint256.Int),
			poolStateSlot:       new(uint256.Int),
			positionMappingSlot: new(uint256.Int),
			tickMappingSlot:     new(uint256.Int),
			tickStateSlot:       new(uint256.Int),
			feeGrowthGlobal0:    nil,
			feeGrowthGlobal1:    nil,
			sqrtPriceX96:        new(uint256.Int),

			key: pool,

			liquidityNet:   make(map[int]*uint256.Int),
			liquidityGross: make(map[int]*uint256.Int),

			activePositions:        0,
			totalPositionLiquidity: new(uint256.Int),
			positionLiquidity:      new(uint256.Int),
		}
		pcs.processPool(statedb)
		// start liquidity invariant checks
		evmTick := new(uint256.Int)
		visited := make(map[int]bool)
		var tickError *TickError
		var computationErr error
		for tick, balanceGross := range pcs.liquidityGross {
			pcs.slotForTickState(tick)
			tickLiquidity := statedb.GetState(poolManagerAddress, pcs.tickStateSlot.Bytes32())
			// the liquidity is packed into a single word, liquidity net is in the upper 128 bits
			// but the data is big endian, so the lower bits are *later* in the array
			// so here we are extracting liquidity *gross*
			tickLiquidityGross := evmTick.SetBytes(tickLiquidity[16:32])
			if tickLiquidityGross.Cmp(balanceGross) != 0 {
				tickError = &TickError{
					tickNumber: tick,
					expected:   tickLiquidityGross.Hex(),
					actual:     balanceGross.Hex(),
					isGross:    true,
				}
				break
			}
			// now check liquidity net
			balanceNet, exists := pcs.liquidityNet[tick]
			if !exists {
				computationErr = fmt.Errorf("Mismatched keys, have %d in gross, but not in net for pool %s", tick, pool)
				break
			}
			tickLiquidityNet := evmTick.SetBytes(tickLiquidity[0:16])
			// don't forget to sign extend!
			// despite everything being big endian, remember that the sign extend counts from the LSB because sure why not
			pcs.bc.signExtendBit.SetUint64(15) // extend the 15 * 8 + 7 bit, aka the 127th bit
			tickLiquidityNet.ExtendSign(tickLiquidityNet, pcs.bc.signExtendBit)
			if tickLiquidityNet.Cmp(balanceNet) != 0 {
				tickError = &TickError{
					tickNumber: tick,
					expected:   tickLiquidityNet.Hex(),
					actual:     balanceNet.Hex(),
					isGross:    false,
				}
				break
			}
			visited[tick] = true
		}
		// TODO: notify the server of the failure, to update the dashboard as appropriate
		if computationErr != nil {
			poolLogger.Error("Computation failed during checking invariants, clearing for retry", "err", computationErr)
			safeguardState.ResetPool(pool)
			continue
		}

		// pool liquidity
		pcs.poolStateSlot.AddUint64(pcs.poolStateSlot, storageOffsets.liquidityOffset)
		rawLiq := statedb.GetState(poolManagerAddress, pcs.poolStateSlot.Bytes32())
		poolLiquidity := pcs.positionLiquidity.SetBytes(rawLiq[:])

		liquidityInvariantHolds := pcs.totalPositionLiquidity.Cmp(poolLiquidity) == 0 && tickError == nil
		updateMessage := getInvariantResult[PoolResult](blockNumber, pcs.key.Hex(), liquidityInvariantHolds,
			getConditionResult(
				"active liquidity", pcs.totalPositionLiquidity.Eq(poolLiquidity), "activePositions", pcs.activePositions, "currentTick", pcs.currTick, "totalLiquidity", pcs.totalPositionLiquidity.Hex(), "poolLiquidity", poolLiquidity.Hex(),
			),
			getConditionResult("tick liquidity", tickError == nil),
		)
		poolLogger.Info("Invariant result", "holds", liquidityInvariantHolds, "pool liquidity", pcs.positionLiquidity, "active position liquidity", pcs.totalPositionLiquidity)
		serverErr := postUpdate(poolUpdateEndpoint, updateMessage)
		if serverErr != nil {
			// logger.Warn("Failed to update web server", "err", serverErr)
		}
	}

	balanceOfSelectorAndPadding, err := hex.DecodeString("70a08231000000000000000000000000")
	if err != nil {
		return err
	}

	owed := new(uint256.Int)
	toAdd := new(uint256.Int)

	for token, tokenState := range safeguardState.tokenAddressToInfo {
		owed.Clear()
		if !tokenState.ready {
			continue
		}
		tokenLogger := logger.With("token", token)
		isIncomplete := false
		for poolKey, _ := range tokenState.poolTokens {
			pState := safeguardState.poolIdToInfo[poolKey]
			if !pState.ready {
				isIncomplete = true
				break
			}
		}
		// this contains the running sum of all the pool balances involved,
		// which is updated incrementally as the pools involved are changed.
		// the other computations here are not worth (imo) incrementalizing, so we
		// do them de novo on each block
		owed.Set(tokenState.poolBalanceOwed)

		// protocol fees
		tokenAccruedSlot := crypto.Keccak256(addressZeroPadding[:], token.Bytes(), storageOffsets.protocolFeesAccruedSlot[:])
		tokenAccruedRaw := statedb.GetState(poolManagerAddress, common.Hash(tokenAccruedSlot))
		toAdd.SetBytes(tokenAccruedRaw[:])
		owed.Add(owed, toAdd)

		// now for transfer events
		for p, _ := range tokenState.balanceOfKeys {
			userBalancesSlot := crypto.Keccak256(addressZeroPadding[:], p.Bytes(), storageOffsets.balanceOfSlot[:])
			balanceOfSlot := crypto.Keccak256(addressZeroPadding[:], token.Bytes(), userBalancesSlot)
			amt := statedb.GetState(poolManagerAddress, common.Hash(balanceOfSlot))
			toAdd.SetBytes(amt[:])
			owed.Add(owed, toAdd)
		}

		// the token amount should now be equal to the sum of balances reqd by positions
		// check that the holds for the pool is correct
		var actualBalance *uint256.Int
		var computationErr error
		if token == etherapi.ZeroAddress {
			// check the native balance then
			actualBalance = statedb.GetBalance(poolManagerAddress)
		} else {
			contract := mr.LoadRealContract(token)
			calldata := append(balanceOfSelectorAndPadding, poolManagerAddress[:]...)
			res, err := mr.RunCode(contract, calldata)
			if err != nil {
				computationErr = err
			} else {
				actualBalance = new(uint256.Int)
				actualBalance.SetBytes(res[0:32])
			}
		}
		// again, log to server, just print for now
		if computationErr != nil {
			tokenLogger.Warn("Failed getting balance of pool", "err", computationErr)
			continue
		}
		invariantHolds := !owed.Gt(actualBalance)
		tokenLogger.Info(fmt.Sprintf("Invariant check status: %s <= %s %t", owed, actualBalance, invariantHolds))
		invariantResult := getInvariantResult[TokenResult](blockNumber, token.Hex(), invariantHolds,
			getConditionResult("solvency", invariantHolds, "requiredBalance", owed.Hex(), "actualBalance", actualBalance.Hex(), "incomplete", isIncomplete),
		)
		serverErr := postUpdate(tokenUpdateEndpoint, invariantResult)
		if serverErr != nil {
			logger.Warn("Failed to update server", "err", serverErr)
		}
	}
	if blockNumber.Uint64()%50 == 0 {
		logger.Debug("Checking complete", "duration", time.Since(start))
	}
	return nil
}

func postUpdate(endPointName string, checkResults map[string]interface{}) error {
	return etherapi.PostUpdate(endPointName, checkResults)
}
