package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/kaspanet/kaspad/cmd/kaspawallet/daemon/client"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/daemon/pb"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/keys"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/libkaspawallet"
	"github.com/pkg/errors"
)

func compound(conf *compoundConfig) error {
	keysFile, err := keys.ReadKeysFile(conf.NetParams(), conf.KeysFile)
	if err != nil {
		return err
	}

	if len(keysFile.ExtendedPublicKeys) > len(keysFile.EncryptedMnemonics) {
		return errors.Errorf("Cannot use 'compound' command for multisig wallet without all of the keys")
	}

	daemonClient, tearDown, err := client.Connect(conf.DaemonAddress)
	if err != nil {
		return err
	}
	defer tearDown()

	ctx, cancel := context.WithTimeout(context.Background(), daemonTimeout)
	defer cancel()

	var toAddress string
	if conf.UsePrimaryAddress {
		// Use the first (primary) external address, creating it if it doesn't exist yet.
		showResp, err := daemonClient.ShowAddresses(ctx, &pb.ShowAddressesRequest{})
		if err != nil {
			return err
		}
		if len(showResp.Address) > 0 {
			toAddress = showResp.Address[0]
		} else {
			newAddrResp, err := daemonClient.NewAddress(ctx, &pb.NewAddressRequest{})
			if err != nil {
				return err
			}
			toAddress = newAddrResp.Address
		}
	} else {
		// Default: generate a fresh address so the consolidated UTXO lands on a clean output.
		newAddrResp, err := daemonClient.NewAddress(ctx, &pb.NewAddressRequest{})
		if err != nil {
			return err
		}
		toAddress = newAddrResp.Address
	}

	// Default to the minimum allowed fee rate (1 sompi/gram) with no total-fee cap.
	// Compounding is never time-sensitive, so paying the minimum is desirable.
	// The daemon's nil-policy default caps total fees at 1 KAS, which is too low
	// when consolidating many UTXOs and causes a fee-rate validation error.
	feePolicy := &pb.FeePolicy{
		FeePolicy: &pb.FeePolicy_ExactFeeRate{ExactFeeRate: 1.0},
	}
	if conf.FeeRate > 0 {
		feePolicy = &pb.FeePolicy{
			FeePolicy: &pb.FeePolicy_ExactFeeRate{ExactFeeRate: conf.FeeRate},
		}
	} else if conf.MaxFeeRate > 0 {
		feePolicy = &pb.FeePolicy{
			FeePolicy: &pb.FeePolicy_MaxFeeRate{MaxFeeRate: conf.MaxFeeRate},
		}
	} else if conf.MaxFee > 0 {
		feePolicy = &pb.FeePolicy{
			FeePolicy: &pb.FeePolicy_MaxFee{MaxFee: conf.MaxFee},
		}
	}

	createResp, err := daemonClient.CreateUnsignedTransactions(ctx, &pb.CreateUnsignedTransactionsRequest{
		Address:   toAddress,
		IsSendAll: true,
		FeePolicy: feePolicy,
	})
	if err != nil {
		return err
	}

	if len(conf.Password) == 0 {
		conf.Password = keys.GetPassword("Password:")
	}
	mnemonics, err := keysFile.DecryptMnemonics(conf.Password)
	if err != nil {
		if strings.Contains(err.Error(), "message authentication failed") {
			fmt.Fprintf(os.Stderr, "Password decryption failed. Sometimes this is a result of not "+
				"specifying the same keys file used by the wallet daemon process.\n")
		}
		return err
	}

	signedTransactions := make([][]byte, len(createResp.UnsignedTransactions))
	for i, unsignedTx := range createResp.UnsignedTransactions {
		signedTx, err := libkaspawallet.Sign(conf.NetParams(), mnemonics, unsignedTx, keysFile.ECDSA)
		if err != nil {
			return err
		}
		signedTransactions[i] = signedTx
	}

	fmt.Printf("Compounding to: %s\n", toAddress)
	fmt.Printf("Broadcasting %d transaction(s)\n", len(signedTransactions))

	// Create a new context for broadcast — the password prompt may have consumed
	// an unbounded amount of the original context's timeout.
	broadcastCtx, broadcastCancel := context.WithTimeout(context.Background(), daemonTimeout)
	defer broadcastCancel()

	const chunkSize = 100 // Stay within gRPC max message size
	for offset := 0; offset < len(signedTransactions); offset += chunkSize {
		end := len(signedTransactions)
		if offset+chunkSize <= len(signedTransactions) {
			end = offset + chunkSize
		}
		chunk := signedTransactions[offset:end]
		response, err := daemonClient.Broadcast(broadcastCtx, &pb.BroadcastRequest{Transactions: chunk})
		if err != nil {
			return err
		}
		fmt.Printf("Broadcasted %d transaction(s) (%.2f%% complete)\n", len(chunk), 100*float64(end)/float64(len(signedTransactions)))
		fmt.Println("Transaction ID(s):")
		for _, txID := range response.TxIDs {
			fmt.Printf("\t%s\n", txID)
		}
	}

	if conf.Verbose {
		fmt.Println("Serialized Transaction(s) (can be parsed via the `parse` command or resent via `broadcast`):")
		for _, signedTx := range signedTransactions {
			fmt.Printf("\t%x\n\n", signedTx)
		}
	}

	return nil
}
