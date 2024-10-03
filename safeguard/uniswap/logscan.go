package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const SWAP = 1
const MODIFY = 2
const INITIALIZE = 4

type LogCallback interface {
	poolFilter(pool common.Hash) bool
	onSwap(pool common.Hash)
	onPosition(tickLower, tickUpper int, positionKey, pool common.Hash)
	onInitialize(poolKey common.Hash, tickSpacing int, fee uint64, currency0, currency1, hooks common.Address)
}

type poolsForToken struct {
	st           *InvariantState
	tokenAddress common.Address
	newPools     map[common.Hash]bool
	tokenState   *TokenState
}

func (p *poolsForToken) InvariantState() *InvariantState {
	return p.st
}

func (p *poolsForToken) NotifyNewPool(poolKey common.Hash) {
	p.newPools[poolKey] = true
}

func (p *poolsForToken) TrackingToken(tok common.Address) *TokenState {
	if tok == p.tokenAddress {
		return p.tokenState
	} else {
		return nil
	}
}

func (p *poolsForToken) onInitialize(poolKey common.Hash, tickSpacing int, fee uint64, currency0, currency1, hooks common.Address) {
	onInitCallback(p, poolKey, tickSpacing, fee, currency0, currency1, hooks)
}

func (p *poolsForToken) poolFilter(pool common.Hash) bool {
	_, ok := p.newPools[pool]
	return ok
}

func (p *poolsForToken) onSwap(pool common.Hash) {
	panic("do not call me")
}

func (p *poolsForToken) onPosition(tickLower, tickUpper int, positionKey, pool common.Hash) {
	p.st.AddPosition(pool, positionKey, tickLower, tickUpper)
}

type positionExtractor struct {
	inv  *InvariantState
	pool common.Hash
}

func (pe *positionExtractor) poolFilter(pool common.Hash) bool {
	return pool == pe.pool
}

func (pe *positionExtractor) onSwap(pool common.Hash) {
	panic("do not call me")
}

func onInitCallback(inv WithInvariantState, poolKey common.Hash, tickSpacing int, fee uint64, currency0, currency1, hooks common.Address) {
	p := inv.InvariantState()
	t := inv.TrackingToken(currency0)
	if t != nil {
		fmt.Printf("Found new pool %s for token %s\n", currency0)
		d, isNew := p.addPool(poolKey, PoolData{
			currency0:   currency0,
			currency1:   currency1,
			tickSpacing: tickSpacing,
			fee:         fee,
			hooks:       hooks,
		})
		// if this is a freshly made pool, then we will see all positions "live", no need to wait
		if isNew {
			inv.NotifyNewPool(poolKey)
			d.ready = true
		}
		d.monitor0 = true
		t.poolTokens[poolKey] = false
	}
	t = inv.TrackingToken(currency1)
	if t != nil {
		fmt.Printf("Found new pool %s for token %s\n", currency1)
		d, isNew := p.addPool(poolKey, PoolData{
			currency0:   currency0,
			currency1:   currency1,
			tickSpacing: tickSpacing,
			fee:         fee,
			hooks:       hooks,
		})
		if isNew {
			inv.NotifyNewPool(poolKey)
			d.ready = true
		}
		d.monitor1 = true
		t.poolTokens[poolKey] = true
	}
}

func (pe *positionExtractor) onPosition(tickLower, tickUpper int, positionKey, pool common.Hash) {
	pe.inv.AddPosition(pool, positionKey, tickLower, tickUpper)
}

func (pe *positionExtractor) onInitialize(poolKey common.Hash, tickSpacing int, fee uint64, currency0, currency1, hooks common.Address) {
	panic("do not call me")
}

func processLogs(
	logs []*types.Log,
	lb LogCallback,
	filt int,
) error {
	for _, l := range logs {
		if l.Address != poolManagerAddress {
			continue
		}
		if len(l.Topics) < 1 {
			continue
		}
		if l.Topics[0] == swapTopic && filt&SWAP != 0 {
			if len(l.Topics) != 3 {
				return fmt.Errorf("Log did not have expected number of topics")
			}
			poolId := l.Topics[1]
			if !lb.poolFilter(poolId) {
				continue
			}
			lb.onSwap(poolId)
		} else if l.Topics[0] == modifyLiquidityTopic && filt&MODIFY != 0 {
			if len(l.Topics) != 3 {
				return fmt.Errorf("Log did not have expected number of topics")
			}
			poolId := l.Topics[1]
			if !lb.poolFilter(poolId) {
				continue
			}
			position := crypto.Keccak256Hash(l.Topics[1][10:32], l.Data[29:32], l.Data[32+29:32+32], l.Data[3*32:4*32])
			lb.onPosition(
				abiToNativeTick(l.Data, 0),
				abiToNativeTick(l.Data, 32),
				position,
				poolId,
			)
		} else if l.Topics[0] == initializeTopic && filt&INITIALIZE != 0 {
			if len(l.Topics) != 4 {
				return fmt.Errorf("Wrong number of topics for initialize event?")
			}
			poolId := l.Topics[1]
			currency0 := common.BytesToAddress(l.Topics[2][:])
			currency1 := common.BytesToAddress(l.Topics[3][:])
			fee := extractBigEndianUint24(l.Data, 29)
			tickSpacing := convert24BitToInt(extractBigEndianUint24(l.Data, 32+29))
			hooks := common.BytesToAddress(l.Data[64 : 64+32])
			lb.onInitialize(poolId, tickSpacing, fee, currency0, currency1, hooks)
		} else {
			continue
		}
	}
	return nil
}

type logMultiExtractor struct {
	inv        *InvariantState
	needsCheck map[common.Hash]bool
}

func (lme *logMultiExtractor) InvariantState() *InvariantState {
	return lme.inv
}

func (lme *logMultiExtractor) NotifyNewPool(pool common.Hash) {
	lme.needsCheck[pool] = true
}

func (lme *logMultiExtractor) TrackingToken(token common.Address) *TokenState {
	t, exists := lme.inv.tokenAddressToInfo[token]
	if exists {
		return t
	} else {
		return nil
	}
}

func (lme *logMultiExtractor) poolFilter(pool common.Hash) bool {
	_, exists := lme.needsCheck[pool]
	return exists
}

func (pe *logMultiExtractor) onSwap(pool common.Hash) {
	pe.needsCheck[pool] = true
}

func (pe *logMultiExtractor) onPosition(tickLower, tickUpper int, positionKey, pool common.Hash) {
	pe.inv.AddPosition(pool, positionKey, tickLower, tickUpper)
	pe.needsCheck[pool] = true
}

func (pe *logMultiExtractor) onInitialize(poolKey common.Hash, tickSpacing int, fee uint64, currency0, currency1, hooks common.Address) {
	onInitCallback(pe, poolKey, tickSpacing, fee, currency0, currency1, hooks)
}
