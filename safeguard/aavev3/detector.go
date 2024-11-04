package main

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/safeguard/dashboard"
	"github.com/ethereum/go-ethereum/safeguard/etherapi"
	"github.com/holiman/uint256"
)

var aavePoolAddress = common.HexToAddress("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2")
var reservesCountSlot = uint256.NewInt(0x3B).Bytes32() // 59 in hex, slot of reserves count
var reservesListSlot = uint256.NewInt(0x36).Bytes32()  // 54 in hex, slot of _reservesList mapping
var reserveDataSlot = uint256.NewInt(0x34).Bytes32()   // 52 in hex, slot of _reserves mapping

var ghoPoolAddress = common.HexToAddress("0x40D16FC0246aD3160Ccc09B8D0D3A2cD28aE6C2f")

var reserveIndexUint = new(uint256.Int)
var reserveDataPointer = new(uint256.Int)

var totalSupplySelector = common.FromHex("0x18160ddd")

var atokenAddressOffset = uint64(4)
var variableDebtTokenOffset = uint64(6)

var aTokenTotalSupply = new(uint256.Int)
var variableDebtTotalSupply = new(uint256.Int)

func readAddressFromStorage(statedb *state.StateDB, where *uint256.Int) common.Address {
	addressRaw := statedb.GetState(aavePoolAddress, where.Bytes32())
	return common.BytesToAddress(addressRaw[:])
}

func runTotalSupplyGetter(mr *etherapi.MockRunner, target common.Address, res *uint256.Int) error {
	contract := mr.LoadRealContract(target)
	ret, err := mr.RunCode(contract, totalSupplySelector)
	if err != nil {
		return fmt.Errorf("Total supply call reverted or failed %s", err)
	}
	if len(ret) != 32 {
		return fmt.Errorf("Unexpected buffer return size %d for totalSupply() on %s", len(ret), target)
	}
	res.SetBytes(ret[0:32])
	return nil
}

func postErrorUpdate(bn big.Int, which common.Address, err error) {
	errMsg := dashboard.GetDashboardErrorMessageGen[dashboard.PlainId, dashboard.NormalizedAddress](
		bn, dashboard.NormalizedAddress(which), err,
	)
	etherapi.PostUpdate("update", errMsg)
}

func invariantChecks(blockNumber big.Int, statedb *state.StateDB, mr *etherapi.MockRunner) error {
	numReservesRaw := statedb.GetState(aavePoolAddress, common.Hash(reservesCountSlot))
	numReserves := new(uint256.Int)
	numReserves.SetBytes(numReservesRaw[:])
	numReserves.Rsh(numReserves, 64)
	numReserve64, overflow := numReserves.Uint64WithOverflow()
	if overflow {
		return fmt.Errorf("Unexpectedly large number of reserves %d", numReserves)
	}
	for i := uint64(0); i < numReserve64; i++ {
		reserveIndexUint.SetUint64(i)
		idxAsBytesArray := reserveIndexUint.Bytes32()
		reserveAddressLocation := crypto.Keccak256Hash(idxAsBytesArray[:], reservesListSlot[:])
		reserveAddressRaw := statedb.GetState(aavePoolAddress, reserveAddressLocation)
		reserveAddress := common.BytesToAddress(reserveAddressRaw[:])
		if reserveAddress == ghoPoolAddress {
			// this is a special exception, gho tokens are hard coded to have no total supply, so skip
			continue
		}
		reserveDataLocationRaw := crypto.Keccak256Hash(reserveAddressRaw[:], reserveDataSlot[:])
		reserveDataPointer.SetBytes(reserveDataLocationRaw[:])
		// read the atoken address
		reserveDataPointer.AddUint64(reserveDataPointer, uint64(atokenAddressOffset))

		atokenAddress := readAddressFromStorage(statedb, reserveDataPointer)
		if atokenAddressOffset >= variableDebtTokenOffset {
			panic("Invariant absolutely broken")
		}

		reserveDataPointer.AddUint64(reserveDataPointer, variableDebtTokenOffset-atokenAddressOffset)
		variableDebtTokenAddress := readAddressFromStorage(statedb, reserveDataPointer)

		err := runTotalSupplyGetter(mr, atokenAddress, aTokenTotalSupply)
		if err != nil {
			postErrorUpdate(blockNumber, reserveAddress, err)
			continue
		}

		err = runTotalSupplyGetter(mr, variableDebtTokenAddress, variableDebtTotalSupply)
		if err != nil {
			postErrorUpdate(blockNumber, reserveAddress, err)
			continue
		}

		violated := aTokenTotalSupply.Lt(variableDebtTotalSupply)
		cond := dashboard.GetConditionResult("totalSupplyGteTotalDebt", !violated,
			"atokenSupply", aTokenTotalSupply,
			"variableDebtSupply", variableDebtTotalSupply,
		)
		etherapi.PostUpdate("update", dashboard.GetDashboardMessageGen[dashboard.PlainId, dashboard.NormalizedAddress](
			blockNumber, dashboard.NormalizedAddress(reserveAddress), !violated, cond,
		))
	}
	return nil
}
