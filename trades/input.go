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

	wETH9Addr = common.HexToAddress("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
)

// tradeParams is the tokens, path (pools involved), and intended amounts of a trade.
type tradeParams struct {
	Recipient common.Address
	SwapToken common.Address
	RxToken   common.Address
	//Path      []*poolHop // all swaps (pools) from swapT to rxT
	//intermediateTokens map[string]struct{}

	SwapAmount *big.Int // AmountIn / AmountInMax
	RxAmount   *big.Int // AmountOut / AmountOutMin

	//rxFixed bool // true: AmountOut, AmountInMax. false: AmountOutMin, AmountIn
}

// poolHop is a single swap (with a pool),
// in a series (path) of swaps of a trade.
type poolHop struct {
	In  common.Address
	Out common.Address
}

// populate swap and rx tokens, and intended trade amounts, from the tx data.
// trades can me single methods with multi hops, OR
// multiple methods for intermediate token swaps if seemingly trading on uniV2 and V3
func (s *service) populateTradeParams(tp *tradeParams, d []byte, sender common.Address) error {
	method, err := s.abiV3Router.MethodById(d)
	if err != nil {
		return errors.Wrap(err, "error getting method by id")
	}
	if method == nil {
		return errors.Errorf("method nil for %x", d)
	}

	fmt.Println("method:", method.Name)

	iArgs := make(map[string]interface{})
	if err = method.Inputs.UnpackIntoMap(iArgs, d[4:]); err != nil {
		return errors.Wrapf(err, "failed to unpack method '%s' input args", method.Name)
	}

	switch method.Name {
	case "multicall0", "multicall1", "multicall":
		dRaw, ok := iArgs["data"]
		if !ok || dRaw == nil {
			return errors.Errorf("unable to get '%s' input data", method.Name)
		}

		dMulti, ok := dRaw.([][]byte)
		if !ok {
			return errors.Errorf("unable to get '%s' input data 2", method.Name)
		}

		for _, d := range dMulti {
			if err = s.populateTradeParams(tp, d, sender); err != nil {
				return err
			}
		}

	case "exactInputSingle":
		fmt.Println("has UniV3 exactInputSingle")
		pRaw, ok := iArgs["params"]
		if !ok || pRaw == nil {
			return errors.New("failed to get exactInputSingle params")
		}

		params := UniswapV3Router2.IV3SwapRouterExactInputSingleParams(pRaw.(struct {
			TokenIn           common.Address `json:"tokenIn"`
			TokenOut          common.Address `json:"tokenOut"`
			Fee               *big.Int       `json:"fee"`
			Recipient         common.Address `json:"recipient"`
			AmountIn          *big.Int       `json:"amountIn"`
			AmountOutMinimum  *big.Int       `json:"amountOutMinimum"`
			SqrtPriceLimitX96 *big.Int       `json:"sqrtPriceLimitX96"`
		}))

		// spew.Dump("exactInputSingle input params:", params)
		return tp.populateTradeMethodParams(
			sender,
			params.Recipient,
			params.TokenIn, params.TokenOut,
			params.AmountIn, params.AmountOutMinimum)

	case "exactInput":
		fmt.Println("has UniV3 exactInput")
		paramsRaw, ok := iArgs["params"]
		if !ok || paramsRaw == nil {
			return errors.New("failed to get exactInput params")
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
			return errors.Wrap(err, "failed to decode MultiSwap Path arg")
		}

		//spew.Dump("with hops:", hops)
		return tp.populateTradeMethodParams(
			sender,
			params.Recipient,
			hops[0].In, hops[len(hops)-1].Out,
			params.AmountIn, params.AmountOutMinimum)

	case "exactOutputSingle":
		fmt.Println("has UniV3 exactOutputSingle")
		paramsRaw, ok := iArgs["params"]
		if !ok || paramsRaw == nil {
			return errors.New("failed to get exactOutputSingle params")
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
		return tp.populateTradeMethodParams(
			sender,
			params.Recipient,
			params.TokenIn, params.TokenOut,
			params.AmountInMaximum, params.AmountOut)

	case "exactOutput":
		fmt.Println("has UniV3 exactOutput")
		paramsRaw, ok := iArgs["params"]
		if !ok || paramsRaw == nil {
			return errors.New("failed to get exactOutput params")
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
			return errors.Wrap(err, "failed to decode MultiSwap Path arg")
		}

		//spew.Dump("with hops:", hops)
		return tp.populateTradeMethodParams(
			sender,
			params.Recipient,
			hops[0].In, hops[len(hops)-1].Out,
			params.AmountInMaximum, params.AmountOut)

	case "swapExactTokensForTokens":
		fmt.Println("is UniV2 swapExactTokensForTokens")
		path := iArgs["path"].([]common.Address)

		//spew.Dump("swapExactTokensForTokens input params:", iArgs)
		return tp.populateTradeMethodParams(
			sender,
			iArgs["to"].(common.Address),
			path[0], path[len(path)-1],
			iArgs["amountIn"].(*big.Int), iArgs["amountOutMin"].(*big.Int))

	case "swapTokensForExactTokens":
		fmt.Println("is UniV2 swapTokensForExactTokens")
		path := iArgs["path"].([]common.Address)

		return tp.populateTradeMethodParams(
			sender,
			iArgs["to"].(common.Address),
			path[0], path[len(path)-1],
			iArgs["amountInMax"].(*big.Int), iArgs["amountOut"].(*big.Int))

	case "unwrapWETH9":
		//spew.Dump("unwrapWETH9 input params:", iArgs)

		recip := iArgs["recipient"].(common.Address)
		if isTheSame(recip, sender) {
			if isSet(tp.RxToken) {
				if !isTheSame(tp.RxToken, wETH9Addr) {
					return errors.New("mixing rx currency with WETH9 Unwrap")
				}
			} else {
				tp.RxToken = wETH9Addr
				tp.Recipient = sender
			}

			tp.RxAmount.Add(tp.RxAmount, iArgs["amountMinimum"].(*big.Int))
		}

	default:
		fmt.Println("warn: uniV3 method not handled:", method.Name)
	}

	return err
}

func (tp *tradeParams) populateTradeMethodParams(sender, recipient, tokenIn, tokenOut common.Address, amtIn, amtOut *big.Int) error {
	recip := inputRecipient(recipient, sender) // TODO: will not get sender== receiver if rx currency uses Withdraw event

	fmt.Printf("trade from %s to %s. recipient: %s. amount in: %s, amount out: %s\n", tokenIn, tokenOut, recip, amtIn.String(), amtOut.String())

	if !isSet(tp.SwapToken) {
		tp.SwapToken = tokenIn

		if isTheSame(recip, sender) {
			if isSet(tp.RxToken) {
				return errors.New("multiple rx tokens 1")
			}

			tp.RxToken = tokenOut
			tp.RxAmount.Add(tp.RxAmount, amtOut)
			tp.Recipient = sender
		} /*else {
			tp.intermediateTokens[tokenOut.Hex()] = struct{}{}
		}*/

		tp.SwapAmount.Add(tp.SwapAmount, amtIn)

	} else { // swap token already set

		if isTheSame(tp.SwapToken, tokenIn) {
			tp.SwapAmount.Add(tp.SwapAmount, amtIn)
		}

		if isTheSame(recip, sender) {
			if isSet(tp.RxToken) {
				if !isTheSame(tp.RxToken, tokenOut) {
					return errors.New("multiple rx tokens 2")
				}
			} else {
				tp.RxToken = tokenOut
				tp.Recipient = sender
			}

			tp.RxAmount.Add(tp.RxAmount, amtOut)
		} /*else {
			tp.intermediateTokens[tokenOut.Hex()] = struct{}{}
		}*/
	}

	// final one should be sender, unless it currenct that uses Withdraw event,
	// then it looks like it would be addrThis.
	/*tp.Recipient = inputRecipient(recipient, sender)

	if firstTradeSet {
		// same initial hop
		if isTheSame(tokenIn, tp.SwapToken) && isTheSame(tokenOut, tp.RxToken) {
			tp.SwapAmount.Add(tp.SwapAmount, amtIn)
			tp.RxAmount.Add(tp.RxAmount, amtOut)
			// intermediate new hop
		} else if isTheSame(tokenIn, tp.RxToken) {
			//tp.Path = append(tp.Path, &poolHop{tp.RxToken, params.TokenOut})
			tp.RxToken = tokenOut // update
			tp.RxAmount = amtOut
			// same intermediary hop
		} else if isTheSame(tokenOut, tp.RxToken) {
			tp.RxAmount.Add(tp.RxAmount, amtOut)
		} else {
			return errors.New("unhandled")
		}
	} else {
		tp.SwapToken = tokenIn
		tp.RxToken = tokenOut
		//tp.Path = []*poolHop{{params.TokenIn, params.TokenOut}}
		tp.SwapAmount = amtIn
		tp.RxAmount = amtOut
		//tp.rxFixed = false
	}*/
	return nil
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
