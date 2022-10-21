package trades

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/RoanBrand/UniswapScanner/abi/UniswapV2Pair"
	"github.com/RoanBrand/UniswapScanner/abi/UniswapV3Pool"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/pkg/errors"
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

// tradedAmounts has the actual amounts exchanged of a trade, after it got executed.
type tradedAmounts struct {
	Recipient  common.Address
	SwapAmount *big.Int
	RxAmount   *big.Int
}

// build/get final amounts debited from and credited to trading wallet during the trade.
func (s *service) getTradedAmounts(logs []*types.Log, sender common.Address, si *tradeParams) (final *tradedAmounts, err error) {
	final = &tradedAmounts{
		SwapAmount: new(big.Int),
		RxAmount:   new(big.Int),
	}

	for _, l := range logs {
		switch l.Topics[0].Hex() {
		case uni3EventTopicDeposit:
			if isTheSame(l.Address, si.SwapToken) {
				/*if final.SwapAmount.Cmp(zero) != 0 {
					return nil, errors.Errorf("event Deposit: swapAmount already populated with %s, want to put in %s", final.SwapAmount.String(), new(big.Int).SetBytes(l.Data).String())
				}
				final.SwapAmount = new(big.Int).SetBytes(l.Data)*/
				final.SwapAmount.Add(final.SwapAmount, new(big.Int).SetBytes(l.Data))
			}
		case uni3EventTopicWithdraw:
			if isTheSame(l.Address, si.RxToken) && isTheSameHashLogAndHexAddress(l.Topics[1], uniV3Addr) {
				/*if final.RxAmount.Cmp(zero) != 0 {
					return nil, errors.Errorf("event Withdraw: rxAmount already populated with %s, want to put in %s", final.RxAmount.String(), new(big.Int).SetBytes(l.Data).String())
				}
				final.RxAmount = new(big.Int).SetBytes(l.Data)*/
				final.RxAmount.Add(final.RxAmount, new(big.Int).SetBytes(l.Data))
				final.Recipient = sender
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
					final.Recipient = sender
				} else {
					final.Recipient = common.BytesToAddress(l.Topics[2].Bytes()) // other receiver of trade proceeds
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

func (s *service) decodeUniV3SwapEventLog(l *types.Log, ps *poolHop) (*tradedAmounts, error) {
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
