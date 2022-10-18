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
	web3Url   = ""
	uniV3Addr = "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"

	confirmations uint64 = 267

	uni2SwapEventTopic = "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"
	uni3SwapEventTopic = "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67"
)

var ()

type service struct {
	ctx context.Context
	c   *ethclient.Client

	abiV3Router *abi.ABI
	abiV3Pool   *abi.ABI
	abiV2Pair   *abi.ABI

	got bool
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

	s := service{ctx, c, &abiV3Router, &abiV3Pool, &abiV2Pair, false}

	/*header, err := c.HeaderByNumber(ctx, nil)
	if err != nil {
		log.Println(errors.Wrap(err, "failed to get latest block"))
		return
	}*/

	blockN := uint64(15767617) //header.Number.Uint64() - confirmations
	block, err := c.BlockByNumber(ctx, new(big.Int).SetUint64(blockN))
	if err != nil {
		log.Println(errors.Wrapf(err, "failed to get block %d from node", blockN))
		return
	}

	for _, tx := range block.Transactions() {
		if err = s.decodeTx(tx); err != nil {
			log.Println(errors.Wrap(err, "failed to decode tx"))
			return
		}

		if s.got {
			log.Println("early exit")
			return // temp only one
		}
	}

	log.Printf("Finished scanning all TXs in block %d \n", blockN)
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

	//fmt.Println()
	fmt.Println("TX:", receipt.TxHash.Hex())

	swapInput, err := s.getSwapInput(tx.Data())
	if err != nil {
		return errors.Wrap(err, "failed to get and decode method input args")
	}

	fmt.Println()
	fmt.Println("Swap Input:")
	spew.Dump(swapInput)
	//fmt.Println()
	//fmt.Println("Receipt:", receipt.TxHash)
	//spew.Dump(receipt)

	swapEv, err := s.getSwapEvent(receipt.Logs, swapInput)
	if err != nil {
		return err
	}

	fmt.Println("Swap Event:")
	spew.Dump(swapEv)
	fmt.Println()

	return nil
}

// poolSwap is a single swap (with a pool),
// in a series (path) of swaps of a trade.
type poolSwap struct {
	In  common.Address
	Out common.Address
}

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

	/*fmt.Println("method name:", method.Name)
	//spew.Dump(tx)
	fmt.Println()
	fmt.Println("Inputs:")
	spew.Dump(inputArgs)
	fmt.Println()*/
}

func getSwapsFromMultiSwapPath(path []byte) (swaps []poolSwap, err error) {
	if len(path) < 3+(2*common.AddressLength) {
		err = errors.New("not long enough for first pool")
		return
	}

	swaps = make([]poolSwap, 1)

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

	//var secondAddr common.Address

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

			paramsAnon := paramsRaw.(struct {
				Path             []uint8        `json:"path"`
				Recipient        common.Address `json:"recipient"`
				AmountIn         *big.Int       `json:"amountIn"`
				AmountOutMinimum *big.Int       `json:"amountOutMinimum"`
			})
			params := UniswapV3Router2.IV3SwapRouterExactInputParams(paramsAnon)

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
				SwapAmount: params.AmountInMaximum,
				RxAmount:   params.AmountOut,
				rxFixed:    true,
			}, nil

		case "swapExactTokensForTokens":
			fmt.Println("is UniV2 swapExactTokensForTokens")
			path := inputArgs["path"].([]common.Address)

			return &swapInput{
				Recipient:  inputArgs["to"].(common.Address),
				SwapToken:  path[0],
				RxToken:    path[len(path)-1],
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

type swapEvent struct {
	Recipient  common.Address
	SwapAmount *big.Int
	RxAmount   *big.Int
}

func (s *service) getSwapEvent(logs []*types.Log, si *swapInput) (*swapEvent, error) {
	for _, l := range logs {
		if t := l.Topics[0].Hex(); t == uni3SwapEventTopic {
			//s.got = true
			return s.decodeUni3Log(l, si)
		} else if t == uni2SwapEventTopic {
			return s.decodeUni2Log(l)
		}
	}

	return nil, errors.New("swap event not found in logs")
}

func (s *service) decodeUni3Log(l *types.Log, si *swapInput) (*swapEvent, error) {
	ev, err := s.abiV3Pool.EventByID(l.Topics[0])
	if err != nil {
		return nil, errors.Wrap(err, "failed to get V3Pool event")
	}

	if ev.Name != "Swap" {
		return nil, errors.New("failed to get V3Pool Swap event. Is: " + ev.Name)
	}

	var uni3PoolSwap UniswapV3Pool.UniswapV3PoolSwap
	err = s.abiV3Pool.UnpackIntoInterface(&uni3PoolSwap, "Swap", l.Data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unpack V3Pool Swap event data")
	}

	var indexed abi.Arguments
	for _, arg := range ev.Inputs {
		if arg.Indexed {
			indexed = append(indexed, arg)
		}
	}

	err = abi.ParseTopics(&uni3PoolSwap, indexed, l.Topics[1:])
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse V3Pool Swap event topics")
	}

	//uni3PoolSwap.Raw = *l

	fmt.Println()
	fmt.Println("uni3 swap deets")
	spew.Dump(&uni3PoolSwap)
	fmt.Println()

	se := swapEvent{
		Recipient: uni3PoolSwap.Recipient,
	}

	if bytes.Compare(si.SwapToken.Bytes(), si.RxToken.Bytes()) == 1 {
		se.SwapAmount = uni3PoolSwap.Amount1
		se.RxAmount = new(big.Int).Abs(uni3PoolSwap.Amount0)
	} else {
		se.SwapAmount = uni3PoolSwap.Amount0
		se.RxAmount = new(big.Int).Abs(uni3PoolSwap.Amount1)
	}

	return &se, nil
}

func (s *service) decodeUni2Log(l *types.Log) (*swapEvent, error) {
	ev, err := s.abiV2Pair.EventByID(l.Topics[0])
	if err != nil {
		return nil, errors.Wrap(err, "failed to get V2Pair event")
	}

	if ev.Name != "Swap" {
		return nil, errors.New("failed to get v2Pair Swap event. Is: " + ev.Name)
	}

	/*fmt.Println()
	fmt.Println("uni2 event", ev.Name, ":")
	spew.Dump(ev)
	fmt.Println()*/

	var uni2PairSwap UniswapV2Pair.UniswapV2PairSwap
	err = s.abiV2Pair.UnpackIntoInterface(&uni2PairSwap, "Swap", l.Data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unpack V2Pair Swap event data")
	}

	var indexed abi.Arguments
	//fmt.Printf("swap event inputs: %+v\n", ev.Inputs)
	for _, arg := range ev.Inputs {
		if arg.Indexed {
			indexed = append(indexed, arg)
		}
	}

	err = abi.ParseTopics(&uni2PairSwap, indexed, l.Topics[1:])
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse V2Pair Swap event topics")
	}

	//uni2PairSwap.Raw = *l

	/*fmt.Println()
	fmt.Println("uni2 swap deets")
	spew.Dump(&uni2PairSwap)
	fmt.Println()*/

	return &swapEvent{
		uni2PairSwap.To,
		uni2SwapAmount(&uni2PairSwap),
		uni2RxAmount(&uni2PairSwap),
	}, nil
}

func uni2SwapAmount(u *UniswapV2Pair.UniswapV2PairSwap) *big.Int {
	if u.Amount0In != nil && u.Amount0In.Uint64() != 0 {
		fmt.Println("uni2 swap event amount0In used")
		return u.Amount0In
	}

	if u.Amount1In != nil && u.Amount1In.Uint64() != 0 {
		fmt.Println("uni2 swap event amount1In used")
		return u.Amount1In
	}

	fmt.Println("CHECK! uni2 swap event no amountIn!")
	return nil
}

func uni2RxAmount(u *UniswapV2Pair.UniswapV2PairSwap) *big.Int {
	if u.Amount0Out != nil && u.Amount0Out.Uint64() != 0 {
		fmt.Println("uni2 swap event Amount0Out used")
		return u.Amount0Out
	}

	if u.Amount1Out != nil && u.Amount1Out.Uint64() != 0 {
		fmt.Println("uni2 swap event Amount1Out used")
		return u.Amount1Out
	}

	fmt.Println("CHECK! uni2 swap event no AmountOut!")
	return nil
}
