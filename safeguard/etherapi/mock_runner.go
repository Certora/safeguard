package etherapi

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"
)

type MockRunner struct {
	db    *state.StateDB
	gas   uint64
	vmenv *vm.EVM
}

var ZeroAddress common.Address

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

func (mr *MockRunner) RunCode(
	contract *vm.Contract,
	calldata []byte,
) ([]byte, error) {
	interp := mr.vmenv.Interpreter()
	return interp.Run(contract, calldata, true)
}

func NewMockRunner(db *state.StateDB, gas uint64, vmenv *vm.EVM) *MockRunner {
	return &MockRunner{
		db:    db,
		vmenv: vmenv,
		gas:   gas,
	}
}
