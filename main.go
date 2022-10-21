package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/RoanBrand/UniswapScanner/trades"

	"github.com/pkg/errors"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill, syscall.SIGTERM)
	defer stop()
	defer log.Println("Exited Program")

	s, err := trades.New(ctx)
	if err != nil {
		log.Println(err)
		return
	}

	defer s.Close()

	if err = s.Run(); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Println("user wants to exit")
		} else {
			fmt.Println("service error:", err)
		}
		return
	}
}
