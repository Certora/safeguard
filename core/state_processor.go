// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"bufio"
	"container/list"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/signal"
	"plugin"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/safeguard/etherapi"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	chain  *HeaderChain        // Canonical header chain
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, chain *HeaderChain) *StateProcessor {
	return &StateProcessor{
		config: config,
		chain:  chain,
	}
}

func (bc *BlockChain) ScanBlocks(lastJsonBlock uint64, ordered bool, cb func([]*types.Log) error) error {
	currHead := bc.CurrentBlock()
	currBlockNum := currHead.Number.Uint64()
	fmt.Printf("Seen %d vs %d\n", lastJsonBlock, currBlockNum)
	if currBlockNum > lastJsonBlock {
		blockMineStart := time.Now()
		logList := list.New()
		headerIt := currHead
		blockNum := currHead.Number.Uint64()
		scannedBlocks := 0
		processLogs := func(ls [][]*types.Log) error {
			for _, txL := range ls {
				if err := cb(txL); err != nil {
					return err
				}
			}
			return nil
		}
		for blockNum > lastJsonBlock {
			currNum := blockNum
			ls := rawdb.ReadLogs(bc.db, headerIt.Hash(), currNum)
			if ordered {
				logList.PushFront(ls)
			} else {
				err := processLogs(ls)
				if err != nil {
					return err
				}
			}
			headerIt = bc.GetHeaderByHash(headerIt.ParentHash)
			blockNum = headerIt.Number.Uint64()
			scannedBlocks++
		}
		if ordered {
			for p := logList.Front(); p != nil; p = p.Next() {
				ls := p.Value.([][]*types.Log)
				err := processLogs(ls)
				if err != nil {
					return err
				}
			}
		}
		fmt.Printf("Scanned %d blocks in %s\n", scannedBlocks, time.Since(blockMineStart))
	}
	return nil
}

type safeguardState struct {
	lock    sync.Mutex
	enabled bool
	impl    etherapi.InvariantChecker
}

var safeguardImpl safeguardState

// must be called holding the lock in s
func (s *safeguardState) pause() {
	old := s.enabled
	s.enabled = false
	if s.impl != nil && old {
		s.impl.OnPause()
	}

}

// must be called holding the lock in s
func (s *safeguardState) unpause() {
	s.enabled = true
}

// acquires and releases lock in s
func (s *safeguardState) reload(p string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	plug, err := plugin.Open(p)
	if err != nil {
		fmt.Printf("Failed to load plugin from %s: %s; pausing checking\n", p, err)
		s.pause()
		return
	}
	sym, err := plug.Lookup("Detector")
	if err != nil {
		fmt.Printf("Failed to find detector implementation in %s: %s; pausing checking\n", p, err)
		s.pause()
		return
	}
	impl, ok := sym.(etherapi.InvariantChecker)
	if !ok {
		fmt.Printf("Detector from %p was not an InvariantChecker, pausing checking\n", p)
		s.pause()
		return
	}
	fmt.Printf("Successfully loaded new implementation, updating pointer, and enabling\n")
	s.enabled = true
	s.impl = impl
}

// acquires and releases lock in s
func (s *safeguardState) flipActivate() {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.impl == nil {
		fmt.Printf("Refusing to change status, no plugin loaded\n")
		return
	}
	currentlyEnabled := s.enabled
	if currentlyEnabled {
		s.pause()
	} else {
		s.unpause()
	}
	fmt.Printf("Enabled status changed: %t -> %t\n", currentlyEnabled, s.enabled)
	return
}

func initSafeguardSignals() {
	fmt.Printf("Setting up signal handlers for process %d\n", os.Getpid())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGUSR2, syscall.SIGUSR1)
	go func(ch chan os.Signal) {
		for s := range ch {
			if s == syscall.SIGUSR1 {
				fmt.Printf("Got request to update checking\n")
				func() {
					p := os.Getenv("SAFEGUARD_PLUGIN_PATH")
					if p == "" {
						fmt.Printf("No safeguard plugin path specified, ignoring load request\n")
						return
					}
					safeguardImpl.reload(p)
				}()
			} else if s == syscall.SIGUSR2 {
				fmt.Printf("Got request to pause/unpause checking\n")
				safeguardImpl.flipActivate()
			} else {
				fmt.Printf("Unexpected signal delivered %s, ignoring\n", s)
			}
		}
	}(signalChan)
}

// Message types
const (
	MessageTypeReload = "RELOAD"
	MessageTypePause  = "PAUSE"
	PluginPathEnv     = "SAFEGUARD_PLUGIN_PATH"
	AdminPathEnv      = "SAFEGUARD_SOCKET_PATH"
	SafeguardModeEnv  = "SAFEGUARD_MODE"
)

// Message struct for IPC
type SafeguardAdminMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
}

// Callback types
type ReloadCallback func(string)
type PauseCallback func()

// safeguardAdminServer struct
type safeguardAdminServer struct {
	reloadCallback ReloadCallback
	pauseCallback  PauseCallback
	socketPath     string
}

// NewIPCServer creates a new IPC server
func newAdminServer(socketPath string, reload ReloadCallback, pause PauseCallback) *safeguardAdminServer {
	return &safeguardAdminServer{
		reloadCallback: reload,
		pauseCallback:  pause,
		socketPath:     socketPath,
	}
}

// Start begins listening for IPC messages
func (s *safeguardAdminServer) start() error {
	// Clean up the socket if it already exists
	if _, err := os.Stat(s.socketPath); !os.IsNotExist(err) {
		if err := os.Remove(s.socketPath); err != nil {
			return fmt.Errorf("failed to remove existing socket @ %s: %w", s.socketPath, err)
		}
	}

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket @ %s: %w", s.socketPath, err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Println("failed to accept connection:", err)
				continue
			}
			go s.handleConnection(conn)
		}
	}()

	return nil
}

// handleConnection processes incoming messages
func (s *safeguardAdminServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	for {
		messageBytes, err := reader.ReadBytes('\n')
		if err == io.EOF {
			return
		}
		if err != nil {
			fmt.Println("failed to read message:", err)
			return
		}

		var message SafeguardAdminMessage
		if err := json.Unmarshal(messageBytes, &message); err != nil {
			fmt.Println("failed to unmarshal message:", err)
			continue
		}

		switch message.Type {
		case MessageTypeReload:
			filePath := strings.TrimSpace(message.Data)
			s.reloadCallback(filePath)
		case MessageTypePause:
			s.pauseCallback()
		default:
			fmt.Println("unknown message type:", message.Type)
		}
	}
}

func initSafeguardSocket() {
	socketPath, exists := os.LookupEnv(AdminPathEnv)
	if !exists {
		fmt.Printf("Socket mode requested, but %s not set: taking no further action\n", AdminPathEnv)
	}
	reload := func(p string) {
		safeguardImpl.reload(p)
	}
	pause := func() {
		safeguardImpl.flipActivate()
	}
	server := newAdminServer(socketPath, reload, pause)
	err := server.start()
	if err != nil {
		fmt.Printf("Failed to start server: %w, taking no further action\n")
	}
}

func init() {
	management, present := os.LookupEnv(SafeguardModeEnv)
	if !present {
		fmt.Printf("%s not set, taking no further action\n", SafeguardModeEnv)
	}
	if management == "SIGNAL" {
		initSafeguardSignals()
	} else if management == "SOCKET" {
		initSafeguardSocket()
	} else if management == "STATIC" {
		p, exists := os.LookupEnv(PluginPathEnv)
		if !exists {
			fmt.Print("Requested static linking, but %s not set, taking no further action\n", PluginPathEnv)
		}
		safeguardImpl.reload(p)
	} else {
		fmt.Printf("Unrecognized safeguard mode: %s, ignoring and taking no further action\n", management)
	}
}


// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config, bc *BlockChain) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts    types.Receipts
		usedGas     = new(uint64)
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = new(GasPool).AddGas(block.GasLimit())
	)

	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	var (
		context vm.BlockContext
		signer  = types.MakeSigner(p.config, header.Number, header.Time)
	)
	context = NewEVMBlockContext(header, p.chain, nil)
	vmenv := vm.NewEVM(context, vm.TxContext{}, statedb, p.config, cfg)
	if beaconRoot := block.BeaconRoot(); beaconRoot != nil {
		ProcessBeaconBlockRoot(*beaconRoot, vmenv, statedb)
	}
	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		msg, err := TransactionToMessage(tx, signer, header.BaseFee)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		statedb.SetTxContext(tx.Hash(), i)

		receipt, err := ApplyTransactionWithEVM(msg, p.config, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	// Fail if Shanghai not enabled and len(withdrawals) is non-zero.
	withdrawals := block.Withdrawals()
	if len(withdrawals) > 0 && !p.config.IsShanghai(block.Number(), block.Time()) {
		return nil, nil, 0, errors.New("withdrawals before shanghai")
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.chain.engine.Finalize(p.chain, header, statedb, block.Body())
	if bc != nil {
		func() {
			safeguardImpl.lock.Lock()
			defer safeguardImpl.lock.Unlock()
			if !safeguardImpl.enabled {
				return
			}
			mr := etherapi.NewMockRunner(
				statedb,
				block.GasLimit(),
				vmenv,
			)
			err := safeguardImpl.impl.InvariantChecks(statedb, bc, *blockNumber, mr, allLogs)
			if err != nil {
				fmt.Printf("Safeguard checking failed with error: %s\n", err)
			}
		}()
	}
	return receipts, allLogs, *usedGas, nil
}

// ApplyTransactionWithEVM attempts to apply a transaction to the given state database
// and uses the input parameters for its environment similar to ApplyTransaction. However,
// this method takes an already created EVM instance as input.
func ApplyTransactionWithEVM(msg *Message, config *params.ChainConfig, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (receipt *types.Receipt, err error) {
	if evm.Config.Tracer != nil && evm.Config.Tracer.OnTxStart != nil {
		evm.Config.Tracer.OnTxStart(evm.GetVMContext(), tx, msg.From)
		if evm.Config.Tracer.OnTxEnd != nil {
			defer func() {
				evm.Config.Tracer.OnTxEnd(receipt, err)
			}()
		}
	}
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, err
	}

	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt = &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	if tx.Type() == types.BlobTxType {
		receipt.BlobGasUsed = uint64(len(tx.BlobHashes()) * params.BlobTxBlobGasPerBlob)
		receipt.BlobGasPrice = evm.Context.BlobBaseFee
	}

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, err
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	msg, err := TransactionToMessage(tx, types.MakeSigner(config, header.Number, header.Time), header.BaseFee)
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := NewEVMBlockContext(header, bc, author)
	txContext := NewEVMTxContext(msg)
	vmenv := vm.NewEVM(blockContext, txContext, statedb, config, cfg)
	return ApplyTransactionWithEVM(msg, config, gp, statedb, header.Number, header.Hash(), tx, usedGas, vmenv)
}

// ProcessBeaconBlockRoot applies the EIP-4788 system call to the beacon block root
// contract. This method is exported to be used in tests.
func ProcessBeaconBlockRoot(beaconRoot common.Hash, vmenv *vm.EVM, statedb *state.StateDB) {
	if vmenv.Config.Tracer != nil && vmenv.Config.Tracer.OnSystemCallStart != nil {
		vmenv.Config.Tracer.OnSystemCallStart()
	}
	if vmenv.Config.Tracer != nil && vmenv.Config.Tracer.OnSystemCallEnd != nil {
		defer vmenv.Config.Tracer.OnSystemCallEnd()
	}

	// If EIP-4788 is enabled, we need to invoke the beaconroot storage contract with
	// the new root
	msg := &Message{
		From:      params.SystemAddress,
		GasLimit:  30_000_000,
		GasPrice:  common.Big0,
		GasFeeCap: common.Big0,
		GasTipCap: common.Big0,
		To:        &params.BeaconRootsAddress,
		Data:      beaconRoot[:],
	}
	vmenv.Reset(NewEVMTxContext(msg), statedb)
	statedb.AddAddressToAccessList(params.BeaconRootsAddress)
	_, _, _ = vmenv.Call(vm.AccountRef(msg.From), *msg.To, msg.Data, 30_000_000, common.U2560)
	statedb.Finalise(true)
}
