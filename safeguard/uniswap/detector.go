package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/safeguard/etherapi"
	"github.com/holiman/uint256"
)

type detectorHandler struct {
	m           *sync.Mutex
	levelVar    *slog.LevelVar
	attr        string
	groupPrefix string
	writer      io.Writer
}

func getHandler(lv *slog.LevelVar) *detectorHandler {
	return &detectorHandler{
		m:           &sync.Mutex{},
		levelVar:    lv,
		attr:        "",
		groupPrefix: "",
		writer:      os.Stdout,
	}
}

func (h *detectorHandler) Enabled(c context.Context, l slog.Level) bool {
	s := h.levelVar.Level()
	return l >= s
}

func (h *detectorHandler) WithGroup(s string) slog.Handler {
	if s == "" {
		return h
	}
	newGroup := h.groupPrefix
	if len(h.groupPrefix) != 0 {
		newGroup += "."
	}
	newGroup += s
	return &detectorHandler{
		m:           h.m,
		levelVar:    h.levelVar,
		attr:        h.attr,
		groupPrefix: newGroup,
		writer:      h.writer,
	}
}

func (h *detectorHandler) WithAttrs(s []slog.Attr) slog.Handler {
	var b strings.Builder
	b.WriteString(h.attr)
	if b.Len() != 0 {
		b.WriteByte(' ')
	}
	needDot := len(h.groupPrefix) > 0
	for _, r := range s {
		if needDot {
			b.WriteString(h.groupPrefix)
			b.WriteByte('.')
		}
		b.WriteString(r.Key)
		b.WriteByte('=')
		b.WriteString(r.Value.String())
	}
	return &detectorHandler{
		m:           h.m,
		attr:        b.String(),
		levelVar:    h.levelVar,
		groupPrefix: h.groupPrefix,
		writer:      h.writer,
	}
}

// no, this is not a bug, this is what a formatting string looks like in Go
const formatString = "[01-02|15:04:05.000]"

func (h *detectorHandler) Handle(c context.Context, r slog.Record) error {
	var b strings.Builder
	level := r.Level.String()
	// no errors
	b.WriteString(level)
	b.WriteByte(' ')
	var t time.Time
	// is there a better way to check for the zero time? I don't know!
	if r.Time != t {
		b.WriteString(r.Time.Format(formatString))
		b.WriteByte(' ')
	}
	b.WriteString(r.Message)
	hasGroup := len(h.groupPrefix) != 0
	r.Attrs(func(a slog.Attr) bool {
		if a.Equal(slog.Attr{}) {
			return true
		}
		if a.Value.Kind() == slog.KindGroup {
			// nah
			return false
		}
		b.WriteByte(' ')
		if hasGroup {
			b.WriteString(h.groupPrefix)
			b.WriteByte('.')
		}
		b.WriteString(a.Key)
		b.WriteByte('=')
		b.WriteString(a.Value.String())
		return true
	})
	if len(h.attr) != 0 {
		b.WriteByte(' ')
		b.WriteByte('(')
		b.WriteString(h.attr)
		b.WriteByte(')')
	}
	b.WriteByte('\n')
	h.m.Lock()
	defer h.m.Unlock()
	h.writer.Write([]byte(b.String()))
	return nil
}

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

var logger = slog.New(getHandler(&levelVar))

var poolSlot = uint256.NewInt(6)

func poolDataOfDict(poolDict map[string]interface{}) (common.Hash, PoolData) {
	poolKey := poolDict["key"].(string)
	key := common.HexToHash(poolKey)
	return key, PoolData{
		tickSpacing: int(poolDict["tickSpacing"].(float64)),
		fee:         uint64(poolDict["fee"].(float64)),
		currency0:   common.HexToAddress(poolDict["currency0"].(string)),
		currency1:   common.HexToAddress(poolDict["currency1"].(string)),
		hooks:       common.HexToAddress(poolDict["hooks"].(string)),
	}
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
    d. The (p,c1) pairs in the token's tokenPools satisfy invariant 7 of getMonitoredPools
*/
func (st *InvariantState) loadTokenPools(tokenAddress common.Address, bc etherapi.BlockScanner, currBlock uint64) ([]common.Hash, error) {
	result := make(map[string]interface{})
	err := etherapi.QueryJsonEndpoint(fmt.Sprintf("token-pools?token=%s", strings.ToLower(tokenAddress.Hex())), &result)
	tokenLogger := logger.With("token", tokenAddress)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch pools for token %s: %s", tokenAddress, err)
	}
	doneRaw, exists := result["done"]
	if !exists {
		return nil, fmt.Errorf("No done status for %s", tokenAddress)
	}
	if !doneRaw.(bool) {
		// nothing to do yet
		return nil, nil
	}
	payloadRaw, exists := result["payload"]
	if !exists {
		return nil, fmt.Errorf("No payload for done result %s", tokenAddress)
	}
	tokenState := st.tokenAddressToInfo[tokenAddress]
	for _, pRaw := range payloadRaw.([]interface{}) {
		p := pRaw.(map[string]interface{})
		key, data := poolDataOfDict(p)
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
	lastBlockRaw, ok := result["lastBlock"]
	if !ok {
		return nil, fmt.Errorf("Missing key lastBlock in JSON")
	}
	lastJsonBlock := uint64(lastBlockRaw.(float64))
	extractor := &poolsForToken{
		tokenAddress: tokenAddress,
		st:           st,
		newPools:     make(map[common.Hash]bool),
		tokenState:   tokenState,
	}
	if lastJsonBlock != 0 {
		err = bc.ScanBlocks(lastJsonBlock, true, func(l []*types.Log) error {
			return processLogs(l, extractor, MODIFY|INITIALIZE)
		})
		if err != nil {
			return nil, err
		}
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
		poolLogger.Info("Initial data not ready yet, trying again later", key)
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
 1. All pool keys that appear in the first list exist in the invariant state PoolIdToInfo
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
		tokenDict := p.(map[string]interface{})
		tokenAddress := tokenDict["address"].(string)
		tokenLogger := logger.With("token", tokenAddress)
		tokenId := common.HexToAddress(tokenAddress)
		tokenData, exists := st.tokenAddressToInfo[tokenId]
		if !exists {
			tokenLogger.Info("Got new request to monitor token")
			tokenData = &TokenState{
				poolTokens: make(map[common.Hash]bool),
				ready:      false,
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
		poolDict := p.(map[string]interface{})
		poolKey := poolDict["key"].(string)
		key := common.HexToHash(poolKey)
		poolState, exists := st.poolIdToInfo[key]
		if !exists {
			logger.Info("New request to monitor pool", "pool", poolKey)
			_, data := poolDataOfDict(poolDict)
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

	err := etherapi.QueryJsonEndpoint(fmt.Sprintf("pool-positions?key=%s", strings.ToLower(pool.Hex())), &root)
	if err != nil {
		return false, err
	}

	stat, exists := root["done"]
	if !exists {
		return false, fmt.Errorf("No done status in result for %s", pool)
	}
	if !stat.(bool) {
		return false, nil
	}

	lastBlockRaw, ok := root["lastBlock"]
	if !ok {
		return false, fmt.Errorf("Missing key lastBlock in JSON")
	}
	lastJsonBlock := uint64(lastBlockRaw.(float64))

	decodedRaw, exists := root["payload"]
	if !exists {
		return false, fmt.Errorf("No payload for done result for %s", pool)
	}
	positionListRaw := decodedRaw

	positionList := positionListRaw.([]interface{})
	pi := st.poolIdToInfo[pool]
	for i, p := range positionList {
		m := p.(map[string]interface{})
		positionBytes, ok := m["positionHash"]
		if !ok {
			return false, fmt.Errorf("Missing position hash from entry %d", i)
		}
		hash := common.HexToHash(positionBytes.(string))
		_, exists := pi.positionsToRange[hash]
		if exists {
			continue
		}
		lowerTick := int(m["tickLower"].(float64))
		upperTick := int(m["tickUpper"].(float64))
		if err != nil {
			return false, fmt.Errorf("Bad upper tick for hash %s: %s", hash, err)
		}
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
	go func() {
		for {
			time.Sleep(time.Duration(5) * time.Second)
			logger.Debug("Hello")
			logger.Info("Hello World")
			logger.Error("Blerp")
		}
	}()
}

var safeguardState InvariantState

var poolManagerAddress = common.HexToAddress("0xE8E23e97Fa135823143d6b9Cba9c699040D51F70")

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
	// indexing stuff, maybe we'll use later
	// m, exists := ps.positionsByRange[r]
	// rangeKeyExists := exists
	// if exists {
	// 	_, exists = m[positionKey]
	// }
	// if exists {
	// 	return
	// }
	// add to indexes
	// ps.positionsByLower[tickLower][r] = true
	// ps.positionsByUpper[tickUpper][r] = true
	// if !rangeKeyExists {
	// 	ps.positionsByRange[r] = map[common.Hash]bool{}
	// }
	// ps.positionsByRange[r][positionKey] = true
	// ps.positionsInterval.Insert(tickLower, tickUpper)
}

func (st *InvariantState) AddPosition(
	poolId, position common.Hash,
	tickLower, tickUpper int,
) {
	pool, _ := st.poolIdToInfo[poolId]
	pool.AddPosition(position, tickLower, tickUpper)
}

// chat gpt wrote this, I hope it's right!
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

const secretPhrase = "fear the old blood, by the gods fear it"

// Helper function to create HMAC signature
func createSignature(data string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

const poolUpdateEndpoint = "pool-update"
const tokenUpdateEndpoint = "token-update"

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

	hashResult := crypto.Keccak256Hash(pcs.tickStateSlot.Bytes(), pcs.tickMappingSlot.Bytes())
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
		pcs.tickStateSlot.AddUint64(pcs.tickStateSlot, 2) // pointing now to feegrowth0
		feeGrowth0 := new(uint256.Int)
		rawRead := db.GetState(poolManagerAddress, pcs.tickStateSlot.Bytes32())
		feeGrowth0.SetBytes(rawRead[:])
		pcs.tickStateSlot.AddUint64(pcs.tickStateSlot, 1) // pointing now to feegrowth1
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

	pcs.slotComputation.AddUint64(pcs.slotComputation, 1) // points now at feegrowthglobal
	raw := db.GetState(poolManagerAddress, pcs.slotComputation.Bytes32())

	pcs.feeGrowthGlobal0 = new(uint256.Int)
	pcs.feeGrowthGlobal0.SetBytes(raw[:])

	pcs.slotComputation.AddUint64(pcs.slotComputation, 1)

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

func invariantChecks(
	statedb *state.StateDB,
	bc etherapi.BlockScanner,
	blockNumber big.Int,
	mr *etherapi.MockRunner,
	allLogs []*types.Log,
) (err error) {
	start := time.Now()
	if safeguardState.poolIdToInfo == nil {
		safeguardState.poolIdToInfo = make(map[common.Hash]*PoolState)
		safeguardState.tokenAddressToInfo = make(map[common.Address]*TokenState)
	}

	defer func() {
		if err != nil {
			safeguardState.Reset()
		}
	}()
	poolsToMonitor, fresh, err := safeguardState.getMonitoredPools(bc, blockNumber.Uint64())
	if err != nil {
		logger.Error("Monitoring task loading failed, clearing all statuses", "err", err)
		return
	}
	needsWork := make(map[common.Hash]bool)
	for _, p := range poolsToMonitor {
		needsWork[p] = false
	}
	/*
	 force a check for all pools that were newly loaded, we know that all such pools must exist in needsWork, by the invariant on getMonitoredPools
	*/
	for _, p := range fresh {
		needsWork[p] = true
	}
	/*
	   All tokens and pools are synced up until the most recent block's logs
	   ingest the most recent logs, adding positions and pools if necessary.
	*/
	err = processLogs(allLogs, &logMultiExtractor{
		inv:        &safeguardState,
		needsCheck: needsWork,
	}, MODIFY|SWAP|INITIALIZE)
	if err != nil {
		return err
	}
	perCheckState := BlockComputationState{
		pc:            getPC(),
		tickCache:     make(map[int]*uint256.Int),
		signExtendBit: new(uint256.Int),
	}
	currency0Owed := make(map[common.Hash]*uint256.Int)
	currency1Owed := make(map[common.Hash]*uint256.Int)

	addToCurrency := func(owedMap map[common.Hash]*uint256.Int, pool common.Hash, amt *uint256.Int) {
		curr, exists := owedMap[pool]
		if !exists {
			curr = new(uint256.Int)
			owedMap[pool] = curr
		}
		curr.Add(curr, amt)
	}
	/*
	   Find those tokens which do not have a running sum yet.
	   Force all involved pools to recompute
	*/
	for _, tokenState := range safeguardState.tokenAddressToInfo {
		if !tokenState.ready {
			continue
		}
		if tokenState.owed == nil {
			for p, isCurrency0 := range tokenState.poolTokens {
				pState := safeguardState.poolIdToInfo[p]
				if !pState.ready {
					continue
				}
				if isCurrency0 && pState.currency0ReqBalance == nil {
					needsWork[p] = true
				} else if !isCurrency0 && pState.currency1ReqBalance == nil {
					needsWork[p] = true
				}
			}
		}
	}

	for pool, doCheck := range needsWork {
		poolLogger := logger.With("pool", pool)
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
		}
		poolState := safeguardState.poolIdToInfo[pool]
		poolLogger.Debug("Working on pool", "monitor0", poolState.monitor0, "monitor1", poolState.monitor1)
		if !poolState.ready {
			poolLogger.Error("Trying to do work on an incomplete pool, this is bad!")
			safeguardState.Reset()
			return Fatal("Invariant broken")
		}
		psBytes := poolSlot.Bytes32()
		poolDataSlot := crypto.Keccak256Hash(pool[:], psBytes[:])
		// get current tick
		slot0value := statedb.GetState(poolManagerAddress, common.Hash(poolDataSlot))

		pcs.poolStateSlot.SetBytes(poolDataSlot[:])
		poolLogger.Debug("Trying to access state", "slot", pcs.poolStateSlot)

		currTick := convert24BitToInt(extractBigEndianUint24(slot0value[:], 9))
		poolLogger.Debug("Pool state", "tick", currTick)
		pcs.sqrtPriceX96.SetBytes(slot0value[12:32])

		if poolState.monitor0 {
			currency0Owed[pool] = new(uint256.Int)
		}
		if poolState.monitor1 {
			currency1Owed[pool] = new(uint256.Int)
		}

		getTickSumIn := func(m map[int]*uint256.Int, tick int) *uint256.Int {
			var toRet *uint256.Int
			var exists bool
			if toRet, exists = m[tick]; !exists {
				toRet = new(uint256.Int)
				m[tick] = toRet
			}
			return toRet
		}

		liquidityGross := make(map[int]*uint256.Int)
		liquidityNet := make(map[int]*uint256.Int)

		totalPositionLiquidity := uint256.NewInt(0)
		positionLiquidity := new(uint256.Int)

		pcs.positionMappingSlot.AddUint64(pcs.poolStateSlot, 6)
		pcs.tickMappingSlot.AddUint64(pcs.poolStateSlot, 4)
		positionMappingSlotRaw := pcs.positionMappingSlot.Bytes32()
		poolLogger.Debug("Pool state", "position slot", common.Hash(positionMappingSlotRaw))

		var activePositions uint64 = 0
		poolLogger.Debug("Pool state", "num positions", len(poolState.positionsToRange))
		logged := false
		for pos, tickRange := range poolState.positionsToRange {
			positionLogger := poolLogger.With("position", pos)
			positionInfoSlot := crypto.Keccak256Hash(pos.Bytes(), positionMappingSlotRaw[:])
			positionLogger.Debug("Position state", "liquidity slot", positionInfoSlot)
			raw := statedb.GetState(poolManagerAddress, positionInfoSlot)
			positionLiquidity.SetBytes(raw.Bytes())
			positionLogger.Debug("Position state", "liquidity", positionLiquidity)
			if positionLiquidity.GtUint64(0) && !logged {
				logged = true
				poolLogger.Debug("Have non-zero liquidity in pool")
			}
			if tickRange.tickLower <= currTick && currTick < tickRange.tickUpper {
				activePositions++
				totalPositionLiquidity = totalPositionLiquidity.Add(totalPositionLiquidity, positionLiquidity)
			}
			grossLower := getTickSumIn(liquidityGross, tickRange.tickLower)
			grossLower.Add(grossLower, positionLiquidity)
			grossUpper := getTickSumIn(liquidityGross, tickRange.tickUpper)
			grossUpper.Add(grossUpper, positionLiquidity)

			netLower := getTickSumIn(liquidityNet, tickRange.tickLower)
			netLower.Add(netLower, positionLiquidity)
			netUpper := getTickSumIn(liquidityNet, tickRange.tickUpper)
			netUpper.Sub(netUpper, positionLiquidity)

			// now do some price computations, if needed
			var feeGrowthInside0X, feeGrowthInside1X *uint256.Int = nil, nil
			// loads the fee in the pcs.slotComputation and adds to the currency (0 for inside0 true or 1 for inside1 for false) based on the
			// feeGrowthInside*X fields
			computeFees := func(inside0 bool) *uint256.Int {

				feeGrowthInside0LastRaw := statedb.GetState(poolManagerAddress, pcs.slotComputation.Bytes32())
				feeGrowthInsideLastUint := new(uint256.Int)
				feeGrowthInsideLastUint.SetBytes(feeGrowthInside0LastRaw[:])
				if feeGrowthInside0X == nil {
					feeGrowthInside0X, feeGrowthInside1X = pcs.feeGrowthInside(statedb, currTick, tickRange.tickLower, tickRange.tickUpper)
				}
				positionLogger.Debug("Fee computation parameters",
					"feeGrowthInsideValue", feeGrowthInsideLastUint,
					"feeGrowthInside0X", feeGrowthInside0X,
					"feeGrowthInside1X", feeGrowthInside1X,
					"positionLiquidity", positionLiquidity,
					"tickLower", tickRange.tickLower,
					"tickUpper", tickRange.tickUpper,
					"is currency0?", inside0,
				)
				var feeGrowthToSubtractFrom *uint256.Int
				if inside0 {
					feeGrowthToSubtractFrom = feeGrowthInside0X
				} else {
					feeGrowthToSubtractFrom = feeGrowthInside1X
				}
				feeGrowthInsideLastUint.Sub(feeGrowthToSubtractFrom, feeGrowthInsideLastUint)
				pcs.bc.pc.mulDiv(feeGrowthInsideLastUint, positionLiquidity, pcs.bc.pc.namedConstant.Q128, feeGrowthInsideLastUint)
				if inside0 {
					addToCurrency(currency0Owed, pool, feeGrowthInsideLastUint)
				} else {
					addToCurrency(currency1Owed, pool, feeGrowthInsideLastUint)
				}
				positionLogger.Debug("Fee result", "result", feeGrowthInsideLastUint)
				return feeGrowthInsideLastUint
			}
			positionLogger.Debug("> start fee computation")
			if poolState.monitor0 {
				positionLogger.Debug(">> Start token balance computation", "token", poolState.currency0)
				// hold onto your butts.gif
				pcs.slotComputation.SetBytes(positionInfoSlot[:])
				pcs.slotComputation.AddUint64(pcs.slotComputation, 1)
				scratchUint := computeFees(true)

				// now let's compute how much is owed for this position
				tickLowerPrice := pcs.bc.getSqrtRatioAtTick(tickRange.tickLower)
				tickUpperPrice := pcs.bc.getSqrtRatioAtTick(tickRange.tickUpper)

				positionLogger.Debug(">> Price parameters",
					"token", poolState.currency0,
					"tickLowerPrice", tickLowerPrice,
					"tickUpperPrice", tickUpperPrice,
					"sqrtPriceX96", pcs.sqrtPriceX96,
					"liquidity", positionLiquidity,
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
				pc.getAmount0DeltaRoundDown(positionLiquidity, scratchUint)
				positionLogger.Debug("<< Balance computation finished", "result", scratchUint)
				addToCurrency(currency0Owed, pool, scratchUint)
			}
			if poolState.monitor1 {
				positionLogger.Debug(">> Start token balance computation", "token", poolState.currency1)
				pcs.slotComputation.SetBytes(positionInfoSlot[:])
				pcs.slotComputation.AddUint64(pcs.slotComputation, 2)

				scratchUint := computeFees(false)

				tickLowerPrice := pcs.bc.getSqrtRatioAtTick(tickRange.tickLower)
				tickUpperPrice := pcs.bc.getSqrtRatioAtTick(tickRange.tickUpper)

				positionLogger.Debug(">> Price parameters",
					"token", poolState.currency0,
					"tickLowerPrice", tickLowerPrice,
					"tickUpperPrice", tickUpperPrice,
					"sqrtPriceX96", pcs.sqrtPriceX96,
					"liquidity", positionLiquidity,
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
				pc.getAmount1DeltaRoundDown(positionLiquidity, scratchUint)
				addToCurrency(currency1Owed, pool, scratchUint)
				positionLogger.Debug("<< Balance computation finished", "result", scratchUint)
				// phew
			}
			positionLogger.Debug("< end fee computation")
		}
		if !logged {
			poolLogger.Warn("Found no non-zero liquidity in pool: sus")
		}
		evmTick := new(uint256.Int)
		visited := make(map[int]bool)
		var tickError *TickError
		var computationErr error
		for tick, balanceGross := range liquidityGross {
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
			balanceNet, exists := liquidityNet[tick]
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
		pcs.poolStateSlot.AddUint64(pcs.poolStateSlot, 3)
		rawLiq := statedb.GetState(poolManagerAddress, pcs.poolStateSlot.Bytes32())
		poolLiquidity := positionLiquidity.SetBytes(rawLiq[:])

		liquidityInvariantHolds := totalPositionLiquidity.Cmp(poolLiquidity) == 0
		updateMessage := map[string]interface{}{
			"tickError":       tickError,
			"invariantResult": liquidityInvariantHolds && tickError != nil,
			"currentTick":     currTick,
			"currBlock":       blockNumber.Uint64(),
			"activePositions": activePositions,
			"totalLiquidity":  totalPositionLiquidity.Hex(),
			"poolLiquidity":   poolLiquidity.Hex(),
		}
		poolLogger.Info("Invariant result", "holds", liquidityInvariantHolds, "pool liquidity", positionLiquidity, "active position liquidity", totalPositionLiquidity)
		serverErr := postUpdate(poolUpdateEndpoint, pool.Hex(), updateMessage)
		if serverErr != nil {
			// logger.Warn("Failed to update web server", "err", serverErr)
		}
	}
	deltaMath := new(uint256.Int)
	/*
	  TODO: jtoman factor in 6909 (nice) transfer events
	*/
	balanceOfSelectorAndPadding, err := hex.DecodeString("70a08231000000000000000000000000")
	if err != nil {
		return
	}

	for token, tokenState := range safeguardState.tokenAddressToInfo {
		if !tokenState.ready {
			continue
		}
		tokenLogger := logger.With("token", token)
		isIncremental := tokenState.owed != nil
		isIncomplete := false
		if !isIncremental {
			tokenState.owed = new(uint256.Int)
		}
		getLatestCurrencyGen := func(poolKey common.Hash, workResultMap map[common.Hash]*uint256.Int, fieldGetter func(*PoolState) *uint256.Int) (*uint256.Int, error) {
			if !needsWork[poolKey] {
				p := safeguardState.poolIdToInfo[poolKey]
				req := fieldGetter(p)
				if req == nil {
					return nil, Fatal(fmt.Sprintf("Didn't want to work on pool %s, but it's currency isn't ready?", poolKey))
				}
				return req, nil
			} else {
				owed, exists := workResultMap[poolKey]
				poolInfo := safeguardState.poolIdToInfo[poolKey]
				if !exists {
					return nil, Fatal(fmt.Sprintf("Needed to do work on pool %s for token %s, but we didn't do it %s (%t) and %s (%t)?", poolKey, token, poolInfo.currency0, poolInfo.monitor0, poolInfo.currency1, poolInfo.monitor1))
				}
				return owed, nil
			}
		}
		getLatestCurrency1 := func(poolKey common.Hash) (*uint256.Int, error) {
			return getLatestCurrencyGen(poolKey, currency1Owed, func(ps *PoolState) *uint256.Int { return ps.currency1ReqBalance })
		}
		getLatestCurrency0 := func(poolKey common.Hash) (*uint256.Int, error) {
			return getLatestCurrencyGen(poolKey, currency0Owed, func(ps *PoolState) *uint256.Int { return ps.currency0ReqBalance })
		}

		applyRequiredAmountDelta := func(isCurrency1 bool, poolState *PoolState) error {
			var currAmount, newAmount *uint256.Int
			var exists bool
			if !isCurrency1 {
				currAmount = poolState.currency0ReqBalance
				newAmount, exists = currency0Owed[poolState.key]
				if !exists {
					return Fatal("needed to do work, but didn't actually compute required amounts")
				}
			} else {
				currAmount = poolState.currency1ReqBalance
				newAmount, exists = currency1Owed[poolState.key]
				if !exists {
					return Fatal("needed to do work, but didn't actually compute required amounts")
				}
			}
			if currAmount == nil {
				// then this is a fresh pool, just add the balance directly
				tokenState.owed.Add(tokenState.owed, newAmount)
				return nil
			}
			// otherwise, subtract or add, depending on the difference
			cmp := currAmount.Cmp(newAmount)
			// no change
			if cmp == 0 {
				return nil
			} else if cmp < 0 {
				// currAmount is less than new amount, so compute how much to add
				deltaMath.Sub(newAmount, currAmount)
				tokenState.owed.Add(tokenState.owed, deltaMath)
			} else {
				// currAmount is greater than new amount, so compute how much to subtract
				deltaMath.Sub(currAmount, newAmount)
				tokenState.owed.Sub(tokenState.owed, deltaMath)
			}
			return nil
		}
		for poolKey, isCurrency1 := range tokenState.poolTokens {
			pState := safeguardState.poolIdToInfo[poolKey]
			if !pState.ready {
				isIncomplete = true
				continue
			}
			// this is the easier version
			if !isIncremental {
				var amt *uint256.Int
				if isCurrency1 {
					amt, err = getLatestCurrency1(poolKey)
				} else {
					amt, err = getLatestCurrency0(poolKey)
				}
				if err != nil {
					return
				}
				tokenState.owed.Add(tokenState.owed, amt)
				continue
			}
			// no need to update the incremental amount
			if !needsWork[poolKey] {
				continue
			}
			// otherwise compute the diff
			applyRequiredAmountDelta(isCurrency1, pState)
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
		invariantHolds := !tokenState.owed.Gt(actualBalance)
		tokenLogger.Debug(fmt.Sprintf("Invariant check status: %s <= %s %t", tokenState.owed, actualBalance, invariantHolds))
		payload := map[string]interface{}{
			"currBlock":       blockNumber.Uint64(),
			"invariantResult": invariantHolds,
			"requiredBalance": tokenState.owed.Hex(),
			"actualBalance":   actualBalance.Hex(),
			"incomplete":      isIncomplete,
		}
		serverErr := postUpdate(tokenUpdateEndpoint, token.Hex(), payload)
		if serverErr != nil {
			// logger.Warn("Failed to update server", "err", serverErr)
		}
	}
	// finally, "commit" any existing updates to the currency balances for a pool
	for p, amt := range currency0Owed {
		if safeguardState.poolIdToInfo[p].currency0ReqBalance == nil {
			safeguardState.poolIdToInfo[p].currency0ReqBalance = new(uint256.Int)
		}
		safeguardState.poolIdToInfo[p].currency0ReqBalance.Set(amt)
	}
	for p, amt := range currency1Owed {
		if safeguardState.poolIdToInfo[p].currency1ReqBalance == nil {
			safeguardState.poolIdToInfo[p].currency1ReqBalance = new(uint256.Int)
		}
		safeguardState.poolIdToInfo[p].currency1ReqBalance.Set(amt)
	}
	if blockNumber.Uint64()%50 == 0 {
		logger.Debug("Checking complete", "duration", time.Since(start))
	}
	return nil
}

func postUpdate(endPointName string, keyHex string, checkResults map[string]interface{}) error {
	endpoint := fmt.Sprintf("%s?key=%s", endPointName, keyHex)
	return etherapi.PostUpdate(endpoint, checkResults)
}
