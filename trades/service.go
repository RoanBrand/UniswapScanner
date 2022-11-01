package trades

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"strings"
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
	web3Url = "https://mainnet.infura.io/v3/ca1921f56f88442cadfca449d53afeef"

	confirmations uint64 = 267 // only scan up to (tip - confirmations)
	startBlock    uint64 = 15827318
)

var (
	zero      = new(big.Int)
	uniV3Addr = common.HexToAddress("0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45")
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

func New(ctx context.Context) (*service, error) {
	abiV3Router, err := abi.JSON(strings.NewReader(UniswapV3Router2.UniswapV3Router2MetaData.ABI))
	if err != nil {
		return nil, errors.Wrap(err, "failed parse uniswap v3 router 2 abi")
	}

	abiV3Pool, err := abi.JSON(strings.NewReader(UniswapV3Pool.UniswapV3PoolMetaData.ABI))
	if err != nil {
		return nil, errors.Wrap(err, "failed parse uniswap v3 pool abi")
	}

	abiV2Pair, err := abi.JSON(strings.NewReader(UniswapV2Pair.UniswapV2PairMetaData.ABI))
	if err != nil {
		return nil, errors.Wrap(err, "failed parse uniswap v2 pair abi")
	}

	c, err := ethclient.DialContext(ctx, web3Url)
	if err != nil {
		return nil, errors.Wrap(err, "failed to dial web3")
	}

	return &service{ctx, c, &abiV3Router, &abiV3Pool, &abiV2Pair, time.NewTimer(0), startBlock}, nil
}

func (s *service) Run() error {
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

func (s *service) Close() error {
	s.c.Close()
	return nil
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
	if tx.To() == nil || !isTheSame(*tx.To(), uniV3Addr) {
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

	fmt.Println()
	fmt.Println("New TX:", receipt.TxHash.Hex())

	sender, err := getTxSender(tx)
	if err != nil {
		return errors.Wrap(err, "failed to get TX sender")
	}

	tp := tradeParams{
		SwapAmount: new(big.Int),
		RxAmount:   new(big.Int),
	}

	err = s.populateTradeParams(&tp, tx.Data(), sender)
	if err != nil {
		return errors.Wrap(err, "failed to get and decode method input args")
	}

	if !isSet(tp.Recipient) {
		fmt.Println("input receiver not set. probably because receiver of trade proceeds != tx sender")
		return nil
	}

	if !isSet(tp.SwapToken) || !isSet(tp.RxToken) {
		fmt.Println()
		fmt.Println("Swap Input:")
		spew.Dump(&tp)
		return errors.New("CHECK. input not set")
	}

	tradedAmounts, err := s.getTradedAmounts(receipt.Logs, sender, &tp)
	if err != nil {
		return err
	}

	if !isSet(tradedAmounts.Recipient) || tradedAmounts.SwapAmount.Cmp(zero) == 0 || tradedAmounts.RxAmount.Cmp(zero) == 0 {
		fmt.Println("Swap Input:")
		spew.Dump(&tp)
		fmt.Println()
		fmt.Println("Final Traded amounts:")
		spew.Dump(tradedAmounts)
		return errors.New("CHECK. output not set")
	}

	// to check things while building/debugging:
	/*if swapInput.rxFixed {
		if tradedAmounts.RxAmount.Cmp(zero) == 0 {
			return errors.New("RxAmount not populated")
		}
		if res := swapInput.RxAmount.Cmp(tradedAmounts.RxAmount); res != 0 {
			if res > 0 {
				fmt.Printf("input %s larger than received token %s. Probable reflection token\n", swapInput.RxAmount.String(), tradedAmounts.RxAmount.String())
			} else {
				//return errors.Errorf("CHECK! Wanted received amount %s not gotten %s", swapInput.RxAmount.String(), tradedAmounts.RxAmount.String())
				fmt.Printf("received amount %s larger than requested fixed %s\n", tradedAmounts.RxAmount.String(), swapInput.RxAmount.String())
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
	}*/

	if !isTheSame(tradedAmounts.Recipient, sender) {
		fmt.Println("recipient", tradedAmounts.Recipient, "not the same as sender. ignoring trade")
		return errors.New(":debug") // ignore traders on behalf of other wallets
	}

	/*fmt.Println("Final Traded amounts:")
	spew.Dump(tradedAmounts)
	fmt.Println()*/

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
