package etherapi

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"
)

// Struct used to run *static* code on the EVM in an already deployed contract
type MockRunner struct {
	// The state database, immutable
	db *state.StateDB
	// set to be the gas limit of the block
	gas uint64
	// the vm
	vmenv *vm.EVM
}

var ZeroAddress common.Address

// Loads the contract code at address, and sets the caller to the zero address.
// Use the value returned by this function in RunCode
func (mr *MockRunner) LoadRealContract(
	address common.Address,
) *vm.Contract {
	db := mr.db
	gas := mr.gas
	toRet := vm.NewContract(vm.AccountRef(ZeroAddress), vm.AccountRef(address), uint256.NewInt(0), gas)
	hash := db.GetCodeHash(address)
	code := db.GetCode(address)
	addressPtr := new(common.Address)
	*addressPtr = address
	toRet.SetCallCode(addressPtr, hash, code)
	return toRet
}

// Invoke the contract (usually returned by LoadRealContract) with the given calldata buffer.
// The return buffer is returned, along with the error (which may be non-nil if the call reverts.)
func (mr *MockRunner) RunCode(
	contract *vm.Contract,
	calldata []byte,
) ([]byte, error) {
	interp := mr.vmenv.Interpreter()
	return interp.Run(contract, calldata, true)
}

// Create a new mock runner, do not call from plugins
func NewMockRunner(db *state.StateDB, gas uint64, vmenv *vm.EVM) *MockRunner {
	return &MockRunner{
		db:    db,
		vmenv: vmenv,
		gas:   gas,
	}
}
