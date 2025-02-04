package main

import (
	"fmt"
	"log/slog"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/safeguard/dashboard"
	"github.com/ethereum/go-ethereum/safeguard/etherapi"
	"github.com/ethereum/go-ethereum/safeguard/logging"
	"github.com/holiman/uint256"
)

var levelVar slog.LevelVar
var logger = slog.New(logging.GetHandler(&levelVar))

var (
	// RAY represents 1e27
	RAY = uint256.NewInt(0).Exp(uint256.NewInt(10), uint256.NewInt(27))
	// HALF_RAY represents 1e27/2
	HALF_RAY = uint256.NewInt(0).Div(RAY, uint256.NewInt(2))
	// MAX_UINT256 represents the maximum value of uint256
	MAX_UINT256 = uint256.NewInt(0).Not(uint256.NewInt(0))
	// PERCENTAGE_FACTOR represents 1e4
	PERCENTAGE_FACTOR = uint256.NewInt(0).Exp(uint256.NewInt(10), uint256.NewInt(4))
	// HALF_PERCENTAGE_FACTOR represents 1e4/2
	HALF_PERCENTAGE_FACTOR = uint256.NewInt(0).Div(PERCENTAGE_FACTOR, uint256.NewInt(2))
)

// RayMul performs ray multiplication: a * b / RAY with rounding.
func RayMul(a, b *uint256.Int) (*uint256.Int, error) {
	if b.IsZero() {
		return uint256.NewInt(0), nil
	}
	maxAllowed := uint256.NewInt(0).Sub(MAX_UINT256, HALF_RAY)
	maxAllowed.Div(maxAllowed, b)
	if a.Cmp(maxAllowed) > 0 {
		return nil, fmt.Errorf("ray multiplication overflow")
	}
	result := maxAllowed.Mul(a, b)
	result.Add(result, HALF_RAY)
	result.Div(result, RAY)
	return result, nil
}

// PercentMul performs percentage multiplication: value * percentage / PERCENTAGE_FACTOR with rounding.
func PercentMul(value, percentage *uint256.Int) (*uint256.Int, error) {
	if percentage.IsZero() {
		return uint256.NewInt(0), nil
	}
	maxAllowed := uint256.NewInt(0).Sub(MAX_UINT256, HALF_PERCENTAGE_FACTOR)
	maxAllowed.Div(maxAllowed, percentage)
	if value.Cmp(maxAllowed) > 0 {
		return nil, fmt.Errorf("percentage multiplication overflow")
	}
	result := maxAllowed.Mul(value, percentage)
	result.Add(result, HALF_PERCENTAGE_FACTOR)
	result.Div(result, PERCENTAGE_FACTOR)
	return result, nil
}

var aavePoolAddress = common.HexToAddress("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2")
var reservesCountSlot = uint256.NewInt(0x3B).Bytes32() // 59 in hex, slot of reserves count
var reservesListSlot = uint256.NewInt(0x36).Bytes32()  // 54 in hex, slot of _reservesList mapping
var reserveDataSlot = uint256.NewInt(0x34).Bytes32()   // 52 in hex, slot of _reserves mapping

var ghoPoolAddress = common.HexToAddress("0x40D16FC0246aD3160Ccc09B8D0D3A2cD28aE6C2f")

var reserveIndexUint = new(uint256.Int)
var reserveDataPointer = new(uint256.Int)

var totalSupplySelector = common.FromHex("0x18160ddd")
var scaledTotalSupplySelector = common.FromHex("0xb1bf962d")
var getReserveNormalizedIncomeSelector = common.FromHex("0xd15e0053000000000000000000000000")
var getVirtualUnderlyingBalanceSelector = common.FromHex("0x6fb07f96000000000000000000000000")

var atokenAddressOffset = uint64(4)
var variableDebtTokenOffset = uint64(6)
var accruedToTreasuryOffset = uint64(8)
var variableBorrowIndexOffset = uint64(2) // low bits

var aTokenTotalSupply = new(uint256.Int)
var variableDebtTotalSupply = new(uint256.Int)
var variableDebtScaledTotalSupply = new(uint256.Int)
var reserveNormalizedIncome = new(uint256.Int)  // from getter
var virtualUnderlyingBalance = new(uint256.Int) // from getter
var variableBorrowIndex = new(uint256.Int)
var accruedToTreasury = new(uint256.Int)

var uint128Mask = uint256.MustFromHex("0xffffffffffffffffffffffffffffffff")
var uint16Mask = uint256.MustFromHex("0xffff")

/*
Calculation Overview:

totalATokenSupply = aToken.totalSupply()

accruedToTreasury_in_storage = RayMul(accruedToTreasury, reserveNormalizedIncome)
tmp1 = RayMul(variableDebtScaledTotalSupply, variableBorrowIndex)
tmp2 = variableDebtTotalSupply - tmp1
accruedToTreasury_addition_due_to_update = PercentMul(tmp2, reserveFactor)

Invariant:
  aTokenTotalSupply + accruedToTreasury_in_storage + accruedToTreasury_addition_due_to_update <= variableDebtTotalSupply + virtualUnderlyingBalance
*/

func readAddressFromStorage(statedb *state.StateDB, where *uint256.Int) common.Address {
	addressRaw := statedb.GetState(aavePoolAddress, where.Bytes32())
	return common.BytesToAddress(addressRaw[:])
}

func readUintFromStorage(statedb *state.StateDB, where *uint256.Int) *uint256.Int {
	raw := statedb.GetState(aavePoolAddress, where.Bytes32())
	res := new(uint256.Int)
	res.SetBytes(raw[:])
	return res
}

func runTotalSupplyGetter(mr *etherapi.MockRunner, target common.Address, res *uint256.Int) error {
	contract := mr.LoadRealContract(target)
	ret, err := mr.RunCode(contract, totalSupplySelector)
	if err != nil {
		return fmt.Errorf("total supply call reverted or failed: %s", err)
	}
	if len(ret) != 32 {
		return fmt.Errorf("unexpected return buffer size %d for totalSupply() on %s", len(ret), target)
	}
	res.SetBytes(ret[0:32])
	return nil
}

func runNullaryGetter(mr *etherapi.MockRunner, target common.Address, selector []byte, res *uint256.Int) error {
	contract := mr.LoadRealContract(target)
	ret, err := mr.RunCode(contract, selector)
	if err != nil {
		return fmt.Errorf("getter call reverted or failed: %s", err)
	}
	if len(ret) != 32 {
		return fmt.Errorf("unexpected return buffer size %d for getter on %s", len(ret), target)
	}
	res.SetBytes(ret[0:32])
	return nil
}

func runGetterOnAsset(mr *etherapi.MockRunner, target common.Address, res *uint256.Int, selectorPadded []byte, addr common.Address) error {
	contract := mr.LoadRealContract(target)
	calldata := append(selectorPadded, addr[:]...)
	logger.Debug("Running call", "calldata", common.Bytes2Hex(calldata))
	ret, err := mr.RunCode(contract, calldata)
	if err != nil {
		return fmt.Errorf("getter call reverted or failed: %s", err)
	}
	if len(ret) != 32 {
		return fmt.Errorf("unexpected return buffer size %d for getter on %s", len(ret), target)
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

// --- Helper Functions ---

// toHex converts a *uint256.Int to a hexadecimal string.
func toHex(u *uint256.Int) string {
	// u.Bytes() returns a minimal-length slice; for comparison purposes this is usually enough.
	return fmt.Sprintf("0x%x", u.Bytes())
}

// toDecimal converts a *uint256.Int to a decimal string using math/big.
func toDecimal(u *uint256.Int) string {
	return new(big.Int).SetBytes(u.Bytes()).String()
}

// --- Invariant Check Function ---

func invariantChecks(blockNumber big.Int, statedb *state.StateDB, mr *etherapi.MockRunner) error {
	logger.Debug("Starting invariantChecks", "block", blockNumber)
	numReservesRaw := statedb.GetState(aavePoolAddress, common.Hash(reservesCountSlot))
	numReserves := new(uint256.Int)
	numReserves.SetBytes(numReservesRaw[:])
	numReserves.Rsh(numReserves, 64)
	numReserve64, overflow := numReserves.Uint64WithOverflow()
	if overflow {
		return fmt.Errorf("unexpectedly large number of reserves %d", numReserves)
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
		reserveLogger := logger.With("reserveAddress", reserveAddress)
		reserveLogger.Info("Starting work")
		reserveDataLocationRaw := crypto.Keccak256Hash(reserveAddressRaw[:], reserveDataSlot[:])
		reserveDataPointer.SetBytes(reserveDataLocationRaw[:])

		reserveLogger.Info("Starting storage reads")
		fullConfiguration := readUintFromStorage(statedb, reserveDataPointer)
		reserveFactor := fullConfiguration.And(fullConfiguration.Rsh(fullConfiguration, 64), uint16Mask)
		reserveLogger.Debug("Storage read", "reserveFactor", toHex(reserveFactor), "readFrom", reserveDataPointer)

		reserveDataPointer.AddUint64(reserveDataPointer, uint64(variableBorrowIndexOffset))
		rawIndex := readUintFromStorage(statedb, reserveDataPointer)
		variableBorrowIndex.And(rawIndex, uint128Mask)
		reserveLogger.Debug("Storage read", "variableBorrowIndex", toHex(variableBorrowIndex), "readFrom", reserveDataPointer)

		reserveDataPointer.AddUint64(reserveDataPointer, atokenAddressOffset-variableBorrowIndexOffset)
		atokenAddress := readAddressFromStorage(statedb, reserveDataPointer)
		reserveLogger.Debug("Storage read", "atokenAddress", atokenAddress, "readFrom", reserveDataPointer)

		reserveDataPointer.AddUint64(reserveDataPointer, variableDebtTokenOffset-atokenAddressOffset)
		variableDebtTokenAddress := readAddressFromStorage(statedb, reserveDataPointer)
		reserveLogger.Debug("Storage read", "variableDebtTokenAddress", variableDebtTokenAddress, "readFrom", reserveDataPointer)

		reserveDataPointer.AddUint64(reserveDataPointer, accruedToTreasuryOffset-variableDebtTokenOffset)
		accruedToTreasuryIndex := readUintFromStorage(statedb, reserveDataPointer)
		accruedToTreasury.And(accruedToTreasuryIndex, uint128Mask)
		reserveLogger.Debug("Storage read", "accruedToTreasury", toHex(accruedToTreasury), "readFrom", reserveDataPointer)

		reserveLogger.Info("Storage param reading complete")
		reserveLogger.Info("Starting getters")
		if err := runTotalSupplyGetter(mr, atokenAddress, aTokenTotalSupply); err != nil {
			reserveLogger.Error("Error getting total supply of aToken", "aToken", atokenAddress, "err", err)
			postErrorUpdate(blockNumber, reserveAddress, err)
			continue
		}
		reserveLogger.Debug("Getter run", "target", atokenAddress, "function", "totalSupply()", "result", toHex(aTokenTotalSupply))

		if err := runTotalSupplyGetter(mr, variableDebtTokenAddress, variableDebtTotalSupply); err != nil {
			reserveLogger.Error("Error getting total supply of variable debt token", "err", err)
			postErrorUpdate(blockNumber, reserveAddress, err)
			continue
		}
		reserveLogger.Debug("Getter run", "target", variableDebtTokenAddress, "function", "totalSupply()", "result", toHex(variableDebtTotalSupply))

		if err := runGetterOnAsset(mr, aavePoolAddress, virtualUnderlyingBalance, getVirtualUnderlyingBalanceSelector, reserveAddress); err != nil {
			reserveLogger.Error("Error getting virtual underlying balance", "err", err)
			postErrorUpdate(blockNumber, reserveAddress, err)
			continue
		}
		reserveLogger.Debug("Getter run", "target", aavePoolAddress, "function", "getVirtualUnderlyingBalance(address)", "arg", reserveAddress, "result", toHex(virtualUnderlyingBalance))

		if err := runGetterOnAsset(mr, aavePoolAddress, reserveNormalizedIncome, getReserveNormalizedIncomeSelector, reserveAddress); err != nil {
			reserveLogger.Error("Error getting reserve normalized income", "err", err)
			postErrorUpdate(blockNumber, reserveAddress, err)
			continue
		}
		reserveLogger.Debug("Getter run", "target", aavePoolAddress, "function", "getReserveNormalizedIncome(address)", "arg", reserveAddress, "result", toHex(reserveNormalizedIncome))

		if err := runNullaryGetter(mr, variableDebtTokenAddress, scaledTotalSupplySelector, variableDebtScaledTotalSupply); err != nil {
			reserveLogger.Error("Error getting scaled total supply of variable debt token", "token", variableDebtTokenAddress, "err", err)
			postErrorUpdate(blockNumber, reserveAddress, err)
			continue
		}
		reserveLogger.Info("Done getters")
		reserveLogger.Info("Computation start")

		// Compute intermediate values.
		accruedToTreasury_in_storage, err := RayMul(accruedToTreasury, reserveNormalizedIncome)
		if err != nil {
			reserveLogger.Error("Error calculating accruedToTreasury_in_storage", "accruedToTreasury", toHex(accruedToTreasury), "reserveNormalizedIncome", toHex(reserveNormalizedIncome), "err", err)
			postErrorUpdate(blockNumber, reserveAddress, err)
			continue
		}
		tmp1, err := RayMul(variableDebtScaledTotalSupply, variableBorrowIndex)
		if err != nil {
			reserveLogger.Error("Error calculating RayMul(variableDebtScaledTotalSupply, variableBorrowIndex)", "variableDebtScaledTotalSupply", toHex(variableDebtScaledTotalSupply), "variableBorrowIndex", toHex(variableBorrowIndex), "err", err)
			postErrorUpdate(blockNumber, reserveAddress, err)
			continue
		}
		tmp2 := new(uint256.Int).Sub(variableDebtTotalSupply, tmp1)
		accruedToTreasury_addition_due_to_update, err := PercentMul(tmp2, reserveFactor)
		if err != nil {
			reserveLogger.Error("Error calculating accruedToTreasury_addition_due_to_update", "tmp2", toHex(tmp2), "reserveFactor", toHex(reserveFactor), "err", err)
			postErrorUpdate(blockNumber, reserveAddress, err)
			continue
		}
		lhs := new(uint256.Int).Add(aTokenTotalSupply, accruedToTreasury_in_storage)
		lhs.Add(lhs, accruedToTreasury_addition_due_to_update)
		rhs := new(uint256.Int).Add(variableDebtTotalSupply, virtualUnderlyingBalance)
		delta := new(big.Int).Sub(rhs.ToBig(), lhs.ToBig())
		violated := lhs.Gt(rhs)
		reserveLogger.Debug("Balance check", "LHS (supply+accrued)", toHex(lhs), "RHS (debt+virtual)", toHex(rhs), "delta", delta, "violated", violated)
		reserveLogger.Debug("Invariant status", "violated", violated)

		// If a violation occurs, build a detailed calculation graph with both hex and decimal representations.
		if violated {
			calcGraph := fmt.Sprintf(
				"Calculation Graph for Reserve %s:\n At block number: %s"+
					"  1. aTokenTotalSupply = %s (hex) | %s (dec)\n"+
					"  2. accruedToTreasury (from storage) = %s (hex) | %s (dec)\n"+
					"  3. reserveNormalizedIncome = %s (hex) | %s (dec)\n"+
					"     => accruedToTreasury_in_storage = RayMul(accruedToTreasury, reserveNormalizedIncome) = %s (hex) | %s (dec)\n"+
					"  4. variableDebtScaledTotalSupply = %s (hex) | %s (dec)\n"+
					"  5. variableBorrowIndex = %s (hex) | %s (dec)\n"+
					"     => RayMul(variableDebtScaledTotalSupply, variableBorrowIndex) = %s (hex) | %s (dec)\n"+
					"  6. variableDebtTotalSupply = %s (hex) | %s (dec)\n"+
					"     => tmp2 = variableDebtTotalSupply - RayMul(variableDebtScaledTotalSupply, variableBorrowIndex) = %s (hex) | %s (dec)\n"+
					"  7. reserveFactor = %s (hex) | %s (dec)\n"+
					"     => accruedToTreasury_addition_due_to_update = PercentMul(tmp2, reserveFactor) = %s (hex) | %s (dec)\n"+
					"  8. LHS (aTokenSupplyPlusAccrued) = aTokenTotalSupply + accruedToTreasury_in_storage + accruedToTreasury_addition_due_to_update = %s (hex) | %s (dec)\n"+
					"  9. virtualUnderlyingBalance = %s (hex) | %s (dec)\n"+
					" 10. RHS (variableDebtPlusVirtualBal) = variableDebtTotalSupply + virtualUnderlyingBalance = %s (hex) | %s (dec)\n"+
					" 11. LHS - RHS = %s (dec)\n",
				reserveAddress.Hex(), blockNumber.String(),
				toHex(aTokenTotalSupply), toDecimal(aTokenTotalSupply),
				toHex(accruedToTreasury), toDecimal(accruedToTreasury),
				toHex(reserveNormalizedIncome), toDecimal(reserveNormalizedIncome),
				toHex(accruedToTreasury_in_storage), toDecimal(accruedToTreasury_in_storage),
				toHex(variableDebtScaledTotalSupply), toDecimal(variableDebtScaledTotalSupply),
				toHex(variableBorrowIndex), toDecimal(variableBorrowIndex),
				toHex(tmp1), toDecimal(tmp1),
				toHex(variableDebtTotalSupply), toDecimal(variableDebtTotalSupply),
				toHex(tmp2), toDecimal(tmp2),
				toHex(reserveFactor), toDecimal(reserveFactor),
				toHex(accruedToTreasury_addition_due_to_update), toDecimal(accruedToTreasury_addition_due_to_update),
				toHex(lhs), toDecimal(lhs),
				toHex(virtualUnderlyingBalance), toDecimal(virtualUnderlyingBalance),
				toHex(rhs), toDecimal(rhs),
				delta,
			)
			reserveLogger.Error("Invariant violation detected. Detailed Calculation Graph", "calcGraph", calcGraph)
		}

		cond := dashboard.GetConditionResult("voDelta", !violated,
			"atokenSupplyPlusAccrued", lhs,
			"variableDebtPlusVirtualBal", rhs,
			"delta", delta.String(),
		)
		result := etherapi.PostUpdate("update", dashboard.GetDashboardMessageGen[dashboard.PlainId, dashboard.NormalizedAddress](
			blockNumber, dashboard.NormalizedAddress(reserveAddress), !violated, cond,
		))
		if result != nil {
			reserveLogger.Error("Error posting dashboard update", "result", result)
		}
		reserveLogger.Info("Done")
	}
	return nil
}
