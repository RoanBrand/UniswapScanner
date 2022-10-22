package trades

import (
	"fmt"
	"math/big"

	"github.com/RoanBrand/UniswapScanner/abi/UniswapV3Router2"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

var (
	// https://etherscan.io/address/0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45#code#F23#L11
	addrMsgSender = common.BigToAddress(big.NewInt(1)) // the tx sender
	addrThis      = common.BigToAddress(big.NewInt(2)) // the router
)

// tradeParams is the tokens, path (pools involved), and intended amounts of a trade.
type tradeParams struct {
	Recipient common.Address
	SwapToken common.Address
	RxToken   common.Address
	Path      []*poolHop // all swaps (pools) from swapT to rxT

	SwapAmount *big.Int // AmountIn / AmountInMax
	RxAmount   *big.Int // AmountOut / AmountOutMin

	rxFixed bool // true: AmountOut, AmountInMax. false: AmountOutMin, AmountIn
}

// poolHop is a single swap (with a pool),
// in a series (path) of swaps of a trade.
type poolHop struct {
	In  common.Address
	Out common.Address
}

// get swap and rx tokens, trade path, and intended trade amounts.
func (s *service) getSwapInput(txData []byte, sender common.Address) (*tradeParams, error) {
	method, err := s.abiV3Router.MethodById(txData)
	if err != nil {
		return nil, errors.Wrap(err, "error getting method by id")
	}
	if method == nil {
		return nil, errors.Errorf("method nil for %x", txData)
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

		return s.getSwapInputDataFromUniV3Multicall(data, sender)

	default:
		return nil, errors.New("unhandled method: " + method.Name)
	}
}

// trades can me single methods with multi hops, OR
// multiple methods for intermediate token swaps if seemingly trading on uniV2 and V3
func (s *service) getSwapInputDataFromUniV3Multicall(data [][]byte, sender common.Address) (*tradeParams, error) {
	final := &tradeParams{
		SwapAmount: new(big.Int),
		RxAmount:   new(big.Int),
	}
	firstTradeSet := false

	for _, d := range data {
		method, err := s.abiV3Router.MethodById(d)
		if err != nil {
			return nil, errors.Wrap(err, "error getting uniV3 multicall inner method by id")
		}
		if method == nil {
			return nil, errors.Errorf("uniV3 multicall inner method nil for %x", data)
		}

		inputArgs := make(map[string]interface{})
		err = method.Inputs.UnpackIntoMap(inputArgs, d[4:])
		if err != nil {
			return nil, errors.Wrap(err, "failed to unpack uniV3 multicall inner method input args")
		}

		switch method.Name {
		case "exactInputSingle":
			fmt.Println("has UniV3 exactInputSingle")
			paramsRaw, ok := inputArgs["params"]
			if !ok || paramsRaw == nil {
				return nil, errors.New("failed to get exactInputSingle params")
			}

			params := UniswapV3Router2.IV3SwapRouterExactInputSingleParams(paramsRaw.(struct {
				TokenIn           common.Address `json:"tokenIn"`
				TokenOut          common.Address `json:"tokenOut"`
				Fee               *big.Int       `json:"fee"`
				Recipient         common.Address `json:"recipient"`
				AmountIn          *big.Int       `json:"amountIn"`
				AmountOutMinimum  *big.Int       `json:"amountOutMinimum"`
				SqrtPriceLimitX96 *big.Int       `json:"sqrtPriceLimitX96"`
			}))

			// spew.Dump("exactInputSingle input params:", params)

			// final one should be sender, unless it currenct that uses Withdraw event,
			// then it looks like it would be addrThis.
			final.Recipient = inputRecipient(params.Recipient, sender)

			if firstTradeSet {
				// same initial hop
				if isTheSame(params.TokenIn, final.SwapToken) && isTheSame(params.TokenOut, final.RxToken) {
					final.SwapAmount.Add(final.SwapAmount, params.AmountIn)
					final.RxAmount.Add(final.RxAmount, params.AmountOutMinimum)
					// intermediate new hop
				} else if isTheSame(params.TokenIn, final.RxToken) {
					final.Path = append(final.Path, &poolHop{final.RxToken, params.TokenOut})
					final.RxToken = params.TokenOut // update
					final.RxAmount = params.AmountOutMinimum
					// same intermediary hop
				} else if isTheSame(params.TokenOut, final.RxToken) {
					final.RxAmount.Add(final.RxAmount, params.AmountOutMinimum)
				} else {
					return nil, errors.New("unhandled")
				}
			} else {
				final.SwapToken = params.TokenIn
				final.RxToken = params.TokenOut
				final.Path = []*poolHop{{params.TokenIn, params.TokenOut}}
				final.SwapAmount = params.AmountIn
				final.RxAmount = params.AmountOutMinimum
				final.rxFixed = false

				firstTradeSet = true
			}

		case "exactInput":
			fmt.Println("has UniV3 exactInput")
			paramsRaw, ok := inputArgs["params"]
			if !ok || paramsRaw == nil {
				return nil, errors.New("failed to get exactInput params")
			}

			params := UniswapV3Router2.IV3SwapRouterExactInputParams(paramsRaw.(struct {
				Path             []byte         `json:"path"`
				Recipient        common.Address `json:"recipient"`
				AmountIn         *big.Int       `json:"amountIn"`
				AmountOutMinimum *big.Int       `json:"amountOutMinimum"`
			}))

			//spew.Dump("exactInput input params:", params)

			hops, err := getHopsFromMultiSwapPath(params.Path, false)
			if err != nil {
				return nil, errors.Wrap(err, "failed to decode MultiSwap Path arg")
			}

			//spew.Dump("with paths:", swaps)

			// final one should be sender
			final.Recipient = inputRecipient(params.Recipient, sender)

			if firstTradeSet {
				// same initial hop
				if isTheSame(hops[0].In, final.SwapToken) && isTheSame(hops[len(hops)-1].Out, final.RxToken) {
					final.SwapAmount.Add(final.SwapAmount, params.AmountIn)
					final.RxAmount.Add(final.RxAmount, params.AmountOutMinimum)
					// new intermediary hop
				} else if isTheSame(hops[0].In, final.RxToken) {
					final.Path = append(final.Path, &poolHop{final.RxToken, hops[len(hops)-1].Out})
					final.RxToken = hops[len(hops)-1].Out // update
					final.RxAmount = params.AmountOutMinimum
					// same intermediary hop
				} else if isTheSame(hops[len(hops)-1].Out, final.RxToken) {
					final.RxAmount.Add(final.RxAmount, params.AmountOutMinimum)
				} else {
					return nil, errors.New("unhandled")
				}
			} else {
				final.SwapToken = hops[0].In
				final.RxToken = hops[len(hops)-1].Out
				final.Path = hops
				final.SwapAmount = params.AmountIn
				final.RxAmount = params.AmountOutMinimum
				final.rxFixed = false

				firstTradeSet = true
			}

		case "exactOutputSingle":
			fmt.Println("has UniV3 exactOutputSingle")
			paramsRaw, ok := inputArgs["params"]
			if !ok || paramsRaw == nil {
				return nil, errors.New("failed to get exactOutputSingle params")
			}

			// Cannot assert directly it seems
			params := UniswapV3Router2.IV3SwapRouterExactOutputSingleParams(paramsRaw.(struct {
				TokenIn           common.Address `json:"tokenIn"`
				TokenOut          common.Address `json:"tokenOut"`
				Fee               *big.Int       `json:"fee"`
				Recipient         common.Address `json:"recipient"`
				AmountOut         *big.Int       `json:"amountOut"`
				AmountInMaximum   *big.Int       `json:"amountInMaximum"`
				SqrtPriceLimitX96 *big.Int       `json:"sqrtPriceLimitX96"`
			}))

			//spew.Dump("exactOutputSingle input params:", params)

			// final one should be sender
			final.Recipient = inputRecipient(params.Recipient, sender)

			if firstTradeSet {
				// same initial hop
				if isTheSame(params.TokenIn, final.SwapToken) && isTheSame(params.TokenOut, final.RxToken) {
					final.SwapAmount.Add(final.SwapAmount, params.AmountInMaximum)
					final.RxAmount.Add(final.RxAmount, params.AmountOut)
					// new intermediary hop
				} else if isTheSame(params.TokenIn, final.RxToken) {
					final.Path = append(final.Path, &poolHop{final.RxToken, params.TokenOut})
					final.RxToken = params.TokenOut // update
					final.RxAmount = params.AmountOut
					// same intermediary hop
				} else if isTheSame(params.TokenOut, final.RxToken) {
					final.RxAmount.Add(final.RxAmount, params.AmountOut)
				} else {
					return nil, errors.New("unhandled")
				}
			} else {
				final.SwapToken = params.TokenIn
				final.RxToken = params.TokenOut
				final.Path = []*poolHop{{params.TokenIn, params.TokenOut}}
				final.SwapAmount = params.AmountInMaximum
				final.RxAmount = params.AmountOut
				final.rxFixed = true

				firstTradeSet = true
			}

		case "exactOutput":
			fmt.Println("has UniV3 exactOutput")
			paramsRaw, ok := inputArgs["params"]
			if !ok || paramsRaw == nil {
				return nil, errors.New("failed to get exactInput params")
			}

			params := UniswapV3Router2.IV3SwapRouterExactOutputParams(paramsRaw.(struct {
				Path            []byte         `json:"path"`
				Recipient       common.Address `json:"recipient"`
				AmountOut       *big.Int       `json:"amountOut"`
				AmountInMaximum *big.Int       `json:"amountInMaximum"`
			}))

			//spew.Dump("exactOutput input params:", params)

			hops, err := getHopsFromMultiSwapPath(params.Path, true)
			if err != nil {
				return nil, errors.Wrap(err, "failed to decode MultiSwap Path arg")
			}

			//spew.Dump("with hops:", hops)

			final.Recipient = inputRecipient(params.Recipient, sender)

			if firstTradeSet {
				if isTheSame(hops[0].In, final.SwapToken) && isTheSame(hops[len(hops)-1].Out, final.RxToken) {
					final.SwapAmount.Add(final.SwapAmount, params.AmountInMaximum)
					final.RxAmount.Add(final.RxAmount, params.AmountOut)
				} else if isTheSame(hops[0].In, final.RxToken) { // intermediate hop
					final.Path = append(final.Path, &poolHop{final.RxToken, hops[len(hops)-1].Out})
					final.RxToken = hops[len(hops)-1].Out // update
					final.RxAmount = params.AmountOut
				} else if isTheSame(hops[len(hops)-1].Out, final.RxToken) { // same hop
					final.RxAmount.Add(final.RxAmount, params.AmountOut)
				} else {
					return nil, errors.New("unhandled")
				}
			} else {
				final.SwapToken = hops[0].In
				final.RxToken = hops[len(hops)-1].Out
				final.Path = hops
				final.SwapAmount = params.AmountInMaximum
				final.RxAmount = params.AmountOut
				final.rxFixed = true

				firstTradeSet = true
			}

		case "swapExactTokensForTokens":
			fmt.Println("is UniV2 swapExactTokensForTokens")
			path := inputArgs["path"].([]common.Address)

			//spew.Dump("swapExactTokensForTokens path", path)

			// final one should be sender
			final.Recipient = inputRecipient(inputArgs["to"].(common.Address), sender)

			if firstTradeSet {
				if isTheSame(path[0], final.SwapToken) && isTheSame(path[len(path)-1], final.RxToken) {
					final.SwapAmount.Add(final.SwapAmount, inputArgs["amountIn"].(*big.Int))
					final.RxAmount.Add(final.RxAmount, inputArgs["amountOutMin"].(*big.Int))
				} else if isTheSame(path[0], final.RxToken) { // intermediate hop
					final.Path = append(final.Path, &poolHop{final.RxToken, path[len(path)-1]})
					final.RxToken = path[len(path)-1] // update
					final.RxAmount = inputArgs["amountOutMin"].(*big.Int)
				} else if isTheSame(path[len(path)-1], final.RxToken) { // same hop
					final.RxAmount.Add(final.RxAmount, inputArgs["amountOutMin"].(*big.Int))
				} else {
					return nil, errors.New("unhandled")
				}
			} else {
				final.SwapToken = path[0]
				final.RxToken = path[len(path)-1]
				final.Path = []*poolHop{{path[0], path[len(path)-1]}}
				final.SwapAmount = inputArgs["amountIn"].(*big.Int)
				final.RxAmount = inputArgs["amountOutMin"].(*big.Int)
				final.rxFixed = false

				firstTradeSet = true
			}

		case "swapTokensForExactTokens":
			fmt.Println("is UniV2 swapTokensForExactTokens")
			path := inputArgs["path"].([]common.Address)

			// final one should be sender
			final.Recipient = inputRecipient(inputArgs["to"].(common.Address), sender)

			if firstTradeSet {
				if isTheSame(path[0], final.SwapToken) && isTheSame(path[len(path)-1], final.RxToken) {
					final.SwapAmount.Add(final.SwapAmount, inputArgs["amountInMax"].(*big.Int))
					final.RxAmount.Add(final.RxAmount, inputArgs["amountOut"].(*big.Int))
				} else if isTheSame(path[0], final.RxToken) { // intermediate hop
					final.Path = append(final.Path, &poolHop{final.RxToken, path[len(path)-1]})
					final.RxToken = path[len(path)-1] // update
					final.RxAmount = inputArgs["amountOut"].(*big.Int)
				} else if isTheSame(path[len(path)-1], final.RxToken) { // same hop
					final.RxAmount.Add(final.RxAmount, inputArgs["amountOut"].(*big.Int))
				} else {
					return nil, errors.New("unhandled")
				}
			} else {
				final.SwapToken = path[0]
				final.RxToken = path[len(path)-1]
				final.Path = []*poolHop{{path[0], path[len(path)-1]}}
				final.SwapAmount = inputArgs["amountInMax"].(*big.Int)
				final.RxAmount = inputArgs["amountOut"].(*big.Int)
				final.rxFixed = true

				firstTradeSet = true
			}

		default:
			fmt.Println("warn: uniV3 multicall inner method not handled:", method.Name)
		}
	}

	return final, nil
}

func inputRecipient(swapMethodRecipient, sender common.Address) common.Address {
	if isTheSame(swapMethodRecipient, addrMsgSender) {
		return sender
	}

	return swapMethodRecipient // could also be addrThis
}

// sequence of trades to perform, with hops[0].In the Swap Token and hops[len(hops)-1].Out the Rx Token.
// With 'exactOutput' the input path sequence is reversed.
func getHopsFromMultiSwapPath(path []byte, isReversed bool) (hops []*poolHop, err error) {
	if len(path) < 3+(2*common.AddressLength) {
		err = errors.New("not long enough for first pool")
		return
	}

	hops = make([]*poolHop, 1, 2)
	hops[0] = new(poolHop)

	if isReversed {
		hops[0].Out = common.BytesToAddress(path[:common.AddressLength])
	} else {
		hops[0].In = common.BytesToAddress(path[:common.AddressLength])
	}

	//fmt.Print("multipath swap: {", swaps[0].In.Hex())
	//defer fmt.Println("}")

	iPath := common.AddressLength
	//fee := feeFromPath(path[iPath:])
	iPath += 3
	//fmt.Printf(" - %d - ", fee)

	if isReversed {
		hops[0].In = common.BytesToAddress(path[iPath : iPath+common.AddressLength])
	} else {
		hops[0].Out = common.BytesToAddress(path[iPath : iPath+common.AddressLength])
	}
	iPath += common.AddressLength
	//fmt.Println(swaps[0].Out.Hex())

	// more hops
	for iPath < len(path) {
		if len(path)-iPath < 3+common.AddressLength {
			err = errors.Errorf("not long enough for fee and second address at offset %d", iPath)
			return
		}

		//fee := feeFromPath(path[iPath:])
		iPath += 3
		//fmt.Printf(" - %d - ", fee)

		ph := new(poolHop)
		if isReversed {
			ph.In = common.BytesToAddress(path[iPath : iPath+common.AddressLength])
			ph.Out = hops[len(hops)-1].In
		} else {
			ph.In = hops[len(hops)-1].Out
			ph.Out = common.BytesToAddress(path[iPath : iPath+common.AddressLength])
		}

		hops = append(hops, ph)
		iPath += common.AddressLength

		//fmt.Print(swaps[len(swaps)-1].Out.Hex())
	}

	if isReversed {
		for i, j := 0, len(hops)-1; i < j; i, j = i+1, j-1 {
			hops[i], hops[j] = hops[j], hops[i]
		}
	}
	return
}

func feeFromPath(d []byte) uint32 {
	// uint24. is it big-endian?
	return uint32(d[2]) | uint32(d[1])<<8 | uint32(d[0])<<16
}
