package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/RoanBrand/UniswapScanner/abi/UniswapV2Pair"
	"github.com/RoanBrand/UniswapScanner/abi/UniswapV3Pool"
	"github.com/RoanBrand/UniswapScanner/abi/UniswapV3Router2"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/pkg/errors"
)

const (
	web3Url   = "https://mainnet.infura.io/v3/ca1921f56f88442cadfca449d53afeef"
	uniV3Addr = "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"

	confirmations uint64 = 267 // only scan up to (tip - confirmations)
	startBlock    uint64 = 15767619
)

const (
	// Swap (index_topic_1 address sender, uint256 amount0In, uint256 amount1In, uint256 amount0Out, uint256 amount1Out, index_topic_2 address to)
	uni2EventTopicSwap = "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"

	uni3EventTopicSwap = "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67"

	// Transfer (index_topic_1 address from, index_topic_2 address to, uint256 value)
	uni3EventTopicTransfer = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	// Approval (index_topic_1 address owner, index_topic_2 address spender, uint256 value)
	uni3EventTopicApproval = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

	// Sync (uint112 reserve0, uint112 reserve1)
	uni3EventTopicSync = "0x1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1"

	// Deposit (index_topic_1 address dst, uint256 wad)
	// WETH9
	uni3EventTopicDeposit = "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c"

	// Withdrawal (index_topic_1 address src, uint256 wad)
	// WETH9
	uni3EventTopicWithdraw = "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65"
)

type service struct {
	ctx context.Context
	c   *ethclient.Client

	abiV3Router *abi.ABI
	abiV3Pool   *abi.ABI
	abiV2Pair   *abi.ABI

	timer     *time.Timer
	nextBlock uint64 // to scan
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill, syscall.SIGTERM)
	defer stop()
	defer log.Println("Exited Program")

	abiV3Router, err := abi.JSON(strings.NewReader(UniswapV3Router2.UniswapV3Router2MetaData.ABI))
	if err != nil {
		log.Println(errors.Wrap(err, "failed parse uniswap v3 router 2 abi"))
		return
	}

	abiV3Pool, err := abi.JSON(strings.NewReader(UniswapV3Pool.UniswapV3PoolMetaData.ABI))
	if err != nil {
		log.Println(errors.Wrap(err, "failed parse uniswap v3 pool abi"))
		return
	}

	abiV2Pair, err := abi.JSON(strings.NewReader(UniswapV2Pair.UniswapV2PairMetaData.ABI))
	if err != nil {
		log.Println(errors.Wrap(err, "failed parse uniswap v2 pair abi"))
		return
	}

	c, err := ethclient.DialContext(ctx, web3Url)
	if err != nil {
		log.Println(errors.Wrap(err, "failed to dial web3"))
		return
	}

	defer c.Close()

	s := service{ctx, c, &abiV3Router, &abiV3Pool, &abiV2Pair, time.NewTimer(0), startBlock}

	if err = s.run(); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Println("user wants to exit")
		} else {
			fmt.Println("service error:", err)
		}
		return
	}

}

func (s *service) run() error {
	for {
		header, err := s.c.HeaderByNumber(s.ctx, nil)
		if err != nil {
			return errors.Wrap(err, "failed to get latest block")
		}

		maxBlockN := header.Number.Uint64() - confirmations
		if s.nextBlock > maxBlockN {
			log.Printf("Finished scanning up to latest block %d\nSleeping for a while..", s.nextBlock-1)
			if err = s.sleepCtx(time.Minute * 5); err != nil {
				return err
			}
			continue
		}

		if err = s.processBlocks(maxBlockN); err != nil {
			fmt.Println("failed to process Block:", err)
			if err = s.sleepCtx(time.Minute * 5); err != nil {
				return err
			}
		}
	}
}

func (s *service) processBlocks(uptTo uint64) error {
	for {
		block, err := s.c.BlockByNumber(s.ctx, new(big.Int).SetUint64(s.nextBlock))
		if err != nil {
			return errors.Wrapf(err, "failed to get block %d from node", s.nextBlock)
		}

		fmt.Printf("\n\nBlock %d:\n***************************************************\n", s.nextBlock)
		err = s.decodeBlockTXs(block.Transactions(), s.nextBlock)
		if err != nil {
			return errors.Wrap(err, "failed to decode Block")
		}

		s.nextBlock++
		if s.nextBlock > uptTo {
			return nil
		}
	}
}

func (s *service) decodeBlockTXs(txs types.Transactions, upToBlock uint64) error {
	for _, tx := range txs {
		if err := s.decodeTx(tx); err != nil {
			return errors.Wrap(err, "failed to decode tx")
		}
	}
	return nil
}

func (s *service) decodeTx(tx *types.Transaction) error {
	if tx.To() == nil || tx.To().Hex() != uniV3Addr {
		return nil
	}

	if len(tx.Data()) == 0 {
		return nil
	}

	receipt, err := s.c.TransactionReceipt(s.ctx, tx.Hash())
	if err != nil {
		return errors.Wrap(err, "failed to get tx receipt")
	}

	if receipt.Status != 1 {
		return nil
	}

	fmt.Println("New TX:", receipt.TxHash.Hex())

	swapInput, err := s.getSwapInput(tx.Data())
	if err != nil {
		return errors.Wrap(err, "failed to get and decode method input args")
	}

	fmt.Println()
	fmt.Println("Swap Input:")
	spew.Dump(swapInput)

	sender, err := getTxSender(tx)
	if err != nil {
		return errors.Wrap(err, "failed to get TX sender")
	}

	tradedAmounts, err := s.getTradedAmounts(receipt.Logs, sender, swapInput)
	if err != nil {
		return err
	}

	// to check things while building/debugging:
	if swapInput.rxFixed {
		if tradedAmounts.RxAmount.Cmp(zero) == 0 {
			return errors.New("RxAmount not populated")
		}
		if res := swapInput.RxAmount.Cmp(tradedAmounts.RxAmount); res != 0 {
			if res > 0 {
				fmt.Printf("input %s larger than received token %s. Probable reflection token\n", swapInput.RxAmount.String(), tradedAmounts.RxAmount.String())
			} else {
				return errors.Errorf("CHECK! Wanted received amount %s not gotten %s", swapInput.RxAmount.String(), tradedAmounts.RxAmount.String())
			}
		}
	} else {
		if tradedAmounts.SwapAmount.Cmp(zero) == 0 {
			return errors.New("SwapAmount not populated")
		}
		if res := swapInput.SwapAmount.Cmp(tradedAmounts.SwapAmount); res != 0 {
			if res > 0 {
				fmt.Printf("input %s larger than swapped token %s. Probable reflection token\n", swapInput.SwapAmount.String(), tradedAmounts.SwapAmount.String())
			} else {
				return errors.Errorf("CHECK! Wanted swap amount %s not traded %s", swapInput.SwapAmount.String(), tradedAmounts.SwapAmount.String())
			}

		}
	}

	if tradedAmounts.RxAmount.Cmp(zero) == 0 {
		return errors.New("RxAmount not populated 2")
	}
	if tradedAmounts.SwapAmount.Cmp(zero) == 0 {
		return errors.New("SwapAmount not populated 2")
	}

	fmt.Println("Final Traded amounts:")
	spew.Dump(tradedAmounts)
	fmt.Println()

	return nil
}

func getTxSender(tx *types.Transaction) (from common.Address, err error) {
	var msg types.Message
	msg, err = tx.AsMessage(types.LatestSignerForChainID(tx.ChainId()), nil)
	if err != nil {
		return
	}

	from = msg.From()
	fmt.Println("TX Sender:", from)
	return
}

// poolSwap is a single swap (with a pool),
// in a series (path) of swaps of a trade.
type poolSwap struct {
	In  common.Address
	Out common.Address
}

// swapInput is the tokens, path (pools involved), and intended amounts of a trade.
type swapInput struct {
	Recipient common.Address
	SwapToken common.Address
	RxToken   common.Address
	Path      []poolSwap // all swaps (pools) from swapT to rxT

	SwapAmount *big.Int // AmountIn / AmountInMax
	RxAmount   *big.Int // AmountOut / AmountOutMin

	rxFixed bool // true: AmountOut, AmountInMax. false: AmountOutMin, AmountIn
}

func (s *service) getSwapInput(txData []byte) (*swapInput, error) {
	method, err := s.abiV3Router.MethodById(txData)
	if err != nil {
		return nil, errors.Wrap(err, "error getting method by id")
	}
	if method == nil {
		return nil, fmt.Errorf("method nil for %x", txData)
	}

	fmt.Println("method:", method.Name)

	inputArgs := make(map[string]interface{})
	err = method.Inputs.UnpackIntoMap(inputArgs, txData[4:])
	if err != nil {
		return nil, errors.Wrap(err, "failed to unpack method input args")
	}

	switch method.Name {
	case "multicall0": // multicall(uint256 deadline, bytes[] data)
		dataRaw, ok := inputArgs["data"]
		if !ok || dataRaw == nil {
			return nil, errors.New("unable to get uniswap v3 multicall input data")
		}

		data, ok := dataRaw.([][]byte)
		if !ok {
			return nil, errors.New("unable to get uniswap v3 multicall input data 2")
		}

		return s.getSwapInputDataFromUniV3Multicall(data)

	default:
		return nil, errors.New("unhandled method: " + method.Name)
	}
}

func getSwapsFromMultiSwapPath(path []byte) (swaps []poolSwap, err error) {
	if len(path) < 3+(2*common.AddressLength) {
		err = errors.New("not long enough for first pool")
		return
	}

	swaps = make([]poolSwap, 1, 2)

	// swap token
	swaps[0].In = common.BytesToAddress(path[:common.AddressLength])

	fmt.Print("multipath swap: {", swaps[0].In.Hex())
	defer fmt.Println("}")

	iPath := common.AddressLength
	fee := feeFromPath(path[iPath:])
	iPath += 3
	fmt.Printf(" - %d - ", fee)

	// rx token from first pool
	swaps[0].Out = common.BytesToAddress(path[iPath : iPath+common.AddressLength])
	iPath += common.AddressLength
	fmt.Println(swaps[0].Out.Hex())

	// more hops
	for iPath < len(path) {
		if len(path)-iPath < 3+common.AddressLength {
			err = fmt.Errorf("not long enough for fee and second address at offset %d", iPath)
			return
		}

		fee := feeFromPath(path[iPath:])
		iPath += 3
		fmt.Printf(" - %d - ", fee)

		swaps = append(swaps, poolSwap{
			In:  swaps[len(swaps)-1].Out,
			Out: common.BytesToAddress(path[iPath : iPath+common.AddressLength]),
		})
		iPath += common.AddressLength

		fmt.Print(swaps[len(swaps)-1].Out.Hex())
	}
	return
}

func feeFromPath(d []byte) uint32 {
	// uint24. is it big-endian?
	return uint32(d[2]) | uint32(d[1])<<8 | uint32(d[0])<<16
}

func (s *service) getSwapInputDataFromUniV3Multicall(data [][]byte) (*swapInput, error) {
	for _, d := range data {
		method, err := s.abiV3Router.MethodById(d)
		if err != nil {
			return nil, errors.Wrap(err, "error getting uniV3 multicall inner method by id")
		}
		if method == nil {
			return nil, fmt.Errorf("uniV3 multicall inner method nil for %x", data)
		}

		inputArgs := make(map[string]interface{})
		err = method.Inputs.UnpackIntoMap(inputArgs, d[4:])
		if err != nil {
			return nil, errors.Wrap(err, "failed to unpack uniV3 multicall inner method input args")
		}

		switch method.Name {
		case "exactInputSingle":
			fmt.Println("is UniV3 exactInputSingle")
			paramsRaw, ok := inputArgs["params"]
			if !ok || paramsRaw == nil {
				return nil, errors.New("failed to get exactInputSingle params")
			}
			//spew.Dump("exactInputSingle raw input:", paramsRaw, reflect.TypeOf(paramsRaw), reflect.ValueOf(paramsRaw))

			paramsAnon := paramsRaw.(struct {
				TokenIn           common.Address `json:"tokenIn"`
				TokenOut          common.Address `json:"tokenOut"`
				Fee               *big.Int       `json:"fee"`
				Recipient         common.Address `json:"recipient"`
				AmountIn          *big.Int       `json:"amountIn"`
				AmountOutMinimum  *big.Int       `json:"amountOutMinimum"`
				SqrtPriceLimitX96 *big.Int       `json:"sqrtPriceLimitX96"`
			})
			params := UniswapV3Router2.IV3SwapRouterExactInputSingleParams(paramsAnon)

			return &swapInput{
				Recipient:  params.Recipient,
				SwapToken:  params.TokenIn,
				RxToken:    params.TokenOut,
				Path:       []poolSwap{{params.TokenIn, params.TokenOut}},
				SwapAmount: params.AmountIn,
				RxAmount:   params.AmountOutMinimum,
				rxFixed:    false,
			}, nil

		case "exactInput":
			fmt.Println("is UniV3 exactInput")
			paramsRaw, ok := inputArgs["params"]
			if !ok || paramsRaw == nil {
				return nil, errors.New("failed to get exactInput params")
			}
			//spew.Dump("exactInput raw input:", paramsRaw, reflect.TypeOf(paramsRaw), reflect.ValueOf(paramsRaw))

			params := UniswapV3Router2.IV3SwapRouterExactInputParams(paramsRaw.(struct {
				Path             []byte         `json:"path"`
				Recipient        common.Address `json:"recipient"`
				AmountIn         *big.Int       `json:"amountIn"`
				AmountOutMinimum *big.Int       `json:"amountOutMinimum"`
			}))

			spew.Dump("exactInput params:", params)

			swaps, err := getSwapsFromMultiSwapPath(params.Path)
			if err != nil {
				return nil, errors.WithMessage(err, "failed to decode MultiSwap Path arg")
			}

			return &swapInput{
				Recipient:  params.Recipient,
				SwapToken:  swaps[0].In,
				RxToken:    swaps[len(swaps)-1].Out,
				Path:       swaps,
				SwapAmount: params.AmountIn,
				RxAmount:   params.AmountOutMinimum,
				rxFixed:    false,
			}, nil

		case "exactOutputSingle":
			fmt.Println("is UniV3 exactOutputSingle")
			paramsRaw, ok := inputArgs["params"]
			if !ok || paramsRaw == nil {
				return nil, errors.New("failed to get exactOutputSingle params")
			}
			//spew.Dump("exactOutputSingle raw input:", paramsRaw, reflect.TypeOf(paramsRaw), reflect.ValueOf(paramsRaw))

			// Cannot assert directly it seems
			paramsAnon := paramsRaw.(struct {
				TokenIn           common.Address `json:"tokenIn"`
				TokenOut          common.Address `json:"tokenOut"`
				Fee               *big.Int       `json:"fee"`
				Recipient         common.Address `json:"recipient"`
				AmountOut         *big.Int       `json:"amountOut"`
				AmountInMaximum   *big.Int       `json:"amountInMaximum"`
				SqrtPriceLimitX96 *big.Int       `json:"sqrtPriceLimitX96"`
			})
			params := UniswapV3Router2.IV3SwapRouterExactOutputSingleParams(paramsAnon)

			return &swapInput{
				Recipient:  params.Recipient,
				SwapToken:  params.TokenIn,
				RxToken:    params.TokenOut,
				Path:       []poolSwap{{params.TokenIn, params.TokenOut}},
				SwapAmount: params.AmountInMaximum,
				RxAmount:   params.AmountOut,
				rxFixed:    true,
			}, nil

		case "swapExactTokensForTokens":
			fmt.Println("is UniV2 swapExactTokensForTokens")
			path := inputArgs["path"].([]common.Address)

			spew.Dump("swapExactTokensForTokens path", path)

			return &swapInput{
				Recipient:  inputArgs["to"].(common.Address),
				SwapToken:  path[0],
				RxToken:    path[len(path)-1],
				Path:       []poolSwap{{path[0], path[len(path)-1]}},
				SwapAmount: inputArgs["amountIn"].(*big.Int),
				RxAmount:   inputArgs["amountOutMin"].(*big.Int),
				rxFixed:    false,
			}, nil

		case "swapTokensForExactTokens":
			fmt.Println("is UniV2 swapTokensForExactTokens")
			path := inputArgs["path"].([]common.Address)

			return &swapInput{
				Recipient:  inputArgs["to"].(common.Address),
				SwapToken:  path[0],
				RxToken:    path[len(path)-1],
				Path:       []poolSwap{{path[0], path[len(path)-1]}},
				SwapAmount: inputArgs["amountInMax"].(*big.Int),
				RxAmount:   inputArgs["amountOut"].(*big.Int),
				rxFixed:    true,
			}, nil

		default:
			fmt.Println("warn: uniV3 multicall inner method not handled:", method.Name)
		}
	}

	return nil, errors.New("failed to get swap input data from UniV3 Multicall")
}

// tradedAmounts has the actual amounts exchanged of a trade, after it got executed.
type tradedAmounts struct {
	Recipient  common.Address
	SwapAmount *big.Int
	RxAmount   *big.Int
}

var zero = new(big.Int)

// build/get final amounts debited from and credited to trading wallet during the trade.
func (s *service) getTradedAmounts(logs []*types.Log, sender common.Address, si *swapInput) (final *tradedAmounts, err error) {
	final = &tradedAmounts{
		SwapAmount: new(big.Int),
		RxAmount:   new(big.Int),
	}

	for _, l := range logs {
		switch l.Topics[0].Hex() {
		case uni3EventTopicDeposit:
			if isTheSame(l.Address, si.SwapToken) {
				if final.SwapAmount.Cmp(zero) != 0 {
					return nil, errors.Errorf("event Deposit: swapAmount already populated with %s, want to put in %s", final.SwapAmount.String(), new(big.Int).SetBytes(l.Data).String())
				}
				final.SwapAmount = new(big.Int).SetBytes(l.Data)
			}
		case uni3EventTopicWithdraw:
			if isTheSame(l.Address, si.RxToken) && isTheSameHashLogAndHexAddress(l.Topics[1], uniV3Addr) {
				if final.RxAmount.Cmp(zero) != 0 {
					return nil, errors.Errorf("event Withdraw: rxAmount already populated with %s, want to put in %s", final.RxAmount.String(), new(big.Int).SetBytes(l.Data).String())
				}
				final.RxAmount = new(big.Int).SetBytes(l.Data)
			}
		case uni3EventTopicTransfer:
			if isTheSame(l.Address, si.SwapToken) {
				if isTheSameHashLogAndAddress(l.Topics[1], sender) {
					/*if final.SwapAmount != nil {
						return nil, errors.Errorf("event Transfer: swapAmount already populated with %s, want to put in %s", final.SwapAmount.String(), new(big.Int).SetBytes(l.Data).String())
					}
					final.SwapAmount = new(big.Int).SetBytes(l.Data)*/
					final.SwapAmount.Add(final.SwapAmount, new(big.Int).SetBytes(l.Data))
				}
			} else if isTheSame(l.Address, si.RxToken) {
				if isTheSameHashLogAndAddress(l.Topics[2], sender) {
					/*if final.RxAmount != nil {
						return nil, errors.Errorf("event Transfer: rxAmount already populated with %s, want to put in %s", final.RxAmount.String(), new(big.Int).SetBytes(l.Data).String())
					}
					final.RxAmount = new(big.Int).SetBytes(l.Data)*/
					final.RxAmount.Add(final.RxAmount, new(big.Int).SetBytes(l.Data))
				}
			}

		// ignore 'Swap' events as they do not always match trade paths 1-1, and can perform additional trades depending on their custom logic.
		case uni3EventTopicSwap:
			/*ta, err = s.decodeUniV3SwapEventLog(l, &si.Path[swapEvCnt])
			if err != nil {
				return nil, errors.WithMessage(err, "failed to decode uniswapV3 Swap event log")
			}*/
		case uni2EventTopicSwap:
			/*ta, err = s.decodeUniV2SwapEventLog(l)
			if err != nil {
				return nil, errors.WithMessage(err, "failed to decode uniswapV2 Swap event log")
			}*/

		// ignore known but not useful events
		case uni3EventTopicApproval,
			uni3EventTopicSync:
			continue
		default:
			fmt.Println("warn: uniV3 event log not handled:", l.Topics[0].Hex())
			continue
		}
	}

	return
}

func (s *service) decodeUniV3SwapEventLog(l *types.Log, ps *poolSwap) (*tradedAmounts, error) {
	ev, err := s.abiV3Pool.EventByID(l.Topics[0])
	if err != nil {
		return nil, errors.Wrap(err, "failed to get event")
	}

	if ev.Name != "Swap" {
		return nil, errors.New("not Swap. Is: " + ev.Name)
	}

	var uni3PoolSwap UniswapV3Pool.UniswapV3PoolSwap
	err = s.abiV3Pool.UnpackIntoInterface(&uni3PoolSwap, "Swap", l.Data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unpack event data")
	}

	var indexed abi.Arguments
	for _, arg := range ev.Inputs {
		if arg.Indexed {
			indexed = append(indexed, arg)
		}
	}

	err = abi.ParseTopics(&uni3PoolSwap, indexed, l.Topics[1:])
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse topics")
	}

	//uni3PoolSwap.Raw = *l

	fmt.Println()
	fmt.Println("uni3 raw swap log deets:")
	spew.Dump(&uni3PoolSwap)
	fmt.Println()

	se := tradedAmounts{
		Recipient: uni3PoolSwap.Recipient,
	}

	// with Uniswap V3: token0 is always the one with the smaller address value.
	if bytes.Compare(ps.In.Bytes(), ps.Out.Bytes()) == 1 {
		se.SwapAmount = uni3PoolSwap.Amount1
		se.RxAmount = new(big.Int).Abs(uni3PoolSwap.Amount0)
	} else {
		se.SwapAmount = uni3PoolSwap.Amount0
		se.RxAmount = new(big.Int).Abs(uni3PoolSwap.Amount1)
	}

	return &se, nil
}

func (s *service) decodeUniV2SwapEventLog(l *types.Log) (*tradedAmounts, error) {
	ev, err := s.abiV2Pair.EventByID(l.Topics[0])
	if err != nil {
		return nil, errors.Wrap(err, "failed to get event")
	}

	if ev.Name != "Swap" {
		return nil, errors.New("not Swap. Is: " + ev.Name)
	}

	/*fmt.Println()
	fmt.Println("uni2 event", ev.Name, ":")
	spew.Dump(ev)
	fmt.Println()*/

	var uni2PairSwap UniswapV2Pair.UniswapV2PairSwap
	err = s.abiV2Pair.UnpackIntoInterface(&uni2PairSwap, "Swap", l.Data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unpack event data")
	}

	var indexed abi.Arguments
	for _, arg := range ev.Inputs {
		if arg.Indexed {
			indexed = append(indexed, arg)
		}
	}

	err = abi.ParseTopics(&uni2PairSwap, indexed, l.Topics[1:])
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse topics")
	}

	//uni2PairSwap.Raw = *l

	/*fmt.Println()
	fmt.Println("uni2 swap deets")
	spew.Dump(&uni2PairSwap)
	fmt.Println()*/

	return &tradedAmounts{
		uni2PairSwap.To,
		uni2SwapAmount(&uni2PairSwap),
		uni2RxAmount(&uni2PairSwap),
	}, nil
}

func uni2SwapAmount(u *UniswapV2Pair.UniswapV2PairSwap) *big.Int {
	if u.Amount0In != nil && u.Amount0In.Uint64() != 0 {
		//fmt.Println("uni2 swap event amount0In used")
		return u.Amount0In
	}

	if u.Amount1In != nil && u.Amount1In.Uint64() != 0 {
		//fmt.Println("uni2 swap event amount1In used")
		return u.Amount1In
	}

	fmt.Println("CHECK! uni2 swap event no amountIn!")
	return nil
}

func uni2RxAmount(u *UniswapV2Pair.UniswapV2PairSwap) *big.Int {
	if u.Amount0Out != nil && u.Amount0Out.Uint64() != 0 {
		//fmt.Println("uni2 swap event Amount0Out used")
		return u.Amount0Out
	}

	if u.Amount1Out != nil && u.Amount1Out.Uint64() != 0 {
		//fmt.Println("uni2 swap event Amount1Out used")
		return u.Amount1Out
	}

	fmt.Println("CHECK! uni2 swap event no AmountOut!")
	return nil
}

func (s *service) sleepCtx(d time.Duration) error {
	if !s.timer.Stop() {
		<-s.timer.C
	}
	s.timer.Reset(d)

	select {
	case <-s.ctx.Done():
		if !s.timer.Stop() {
			<-s.timer.C
		}
		return s.ctx.Err()
	case <-s.timer.C:
		return nil
	}
}

func isTheSame(addr1, addr2 common.Address) bool {
	return bytes.Equal(addr1.Bytes(), addr2.Bytes())
}

// quick helper with no allocation
// old: isTheSame(common.BytesToAddress(logHash.Bytes()), addr)
func isTheSameHashLogAndAddress(logHash common.Hash, addr common.Address) bool {
	return bytes.Equal(addr.Bytes(), logHash.Bytes()[common.HashLength-common.AddressLength:])
}

func isTheSameHashLogAndHexAddress(logHash common.Hash, addr string) bool {
	return common.BytesToAddress(logHash.Bytes()).Hex() == addr
}
