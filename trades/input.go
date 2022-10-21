package trades

import (
	"fmt"
	"math/big"

	"github.com/RoanBrand/UniswapScanner/abi/UniswapV3Router2"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

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

// poolSwap is a single swap (with a pool),
// in a series (path) of swaps of a trade.
type poolSwap struct {
	In  common.Address
	Out common.Address
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
