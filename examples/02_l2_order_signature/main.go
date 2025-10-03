package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/kis9a/edgex-stark-signature/pkg/signature"
)

// L2OrderSignatureResult represents the signature output for L2 orders
type L2OrderSignatureResult struct {
	OrderParams signature.OrderParams `json:"order_params"`
	Signature   string                `json:"signature"`
	R           string                `json:"r"`
	S           string                `json:"s"`
}

func main() {
	fmt.Println("=== EdgeX Stark Curve L2 Order Signature Demo ===")
	fmt.Println()

	// Get secret key from environment variable
	secretKey := os.Getenv("EDGEX_SECRET_KEY")
	if secretKey == "" {
		log.Fatal("Error: EDGEX_SECRET_KEY environment variable is not set.\n" +
			"Please set it before running this example:\n" +
			"  export EDGEX_SECRET_KEY=your-secret-key-hex\n" +
			"Or copy .env.example to .env and fill in your credentials.")
	}

	// Example 1: Simple spot trading order
	fmt.Println("Example 1: Simple Spot Trading Order")
	fmt.Println("-------------------------------------")
	example1(secretKey)

	fmt.Println("\n" + repeat("=", 60) + "\n")

	// Example 2: Perpetual futures order
	fmt.Println("Example 2: Perpetual Futures Order")
	fmt.Println("-----------------------------------")
	example2(secretKey)

	fmt.Println("\n" + repeat("=", 60) + "\n")

	// Example 3: Complex order with large amounts
	fmt.Println("Example 3: Complex Order with Large Amounts")
	fmt.Println("--------------------------------------------")
	example3(secretKey)
}

func example1(secretKey string) {
	// Create a simple spot trading order
	// Selling 1 ETH (token 0x1234) for 2500 USDC (token 0x5678)
	orderParams := signature.OrderParams{
		VaultSell:      "1",                                  // Seller's vault ID
		VaultBuy:       "2",                                  // Buyer's vault ID
		AmountSell:     "1000000000000000000",                // 1 ETH (18 decimals)
		AmountBuy:      "2500000000",                         // 2500 USDC (6 decimals)
		TokenSell:      "0x1234",                             // ETH token address (hex)
		TokenBuy:       "0x5678",                             // USDC token address (hex)
		Nonce:          "1",                                  // Nonce for replay protection
		ExpirationTime: strconv.FormatInt(time.Now().Add(24*time.Hour).Unix(), 10), // Expires in 24 hours
		StarkKey:       "",                                   // Optional: Stark public key
		PositionID:     "",                                   // Optional: Position ID for derivatives
		LimitOrderQuantum: "",                                // Optional: Quantum for limit orders
		OraclePrice:    "",                                   // Optional: Oracle price
	}

	signAndDisplay(secretKey, orderParams, "Simple spot trading order: Sell 1 ETH for 2500 USDC")
}

func example2(secretKey string) {
	// Create a perpetual futures order
	// Opening a long position on BTC-PERP
	orderParams := signature.OrderParams{
		VaultSell:         "100",                                                       // Position vault
		VaultBuy:          "101",                                                       // Collateral vault
		AmountSell:        "10000000000",                                               // Position size (synthetic asset)
		AmountBuy:         "500000000000",                                              // Collateral (USDC)
		TokenSell:         "0x4254431234567890abcdef1234567890abcdef1234567890abcdef",  // BTC synthetic token (valid hex)
		TokenBuy:          "0x555344431234567890abcdef1234567890abcdef1234567890abcd",  // USDC collateral (valid hex)
		Nonce:             "42",                                                        // Nonce
		ExpirationTime:    strconv.FormatInt(time.Now().Add(7*24*time.Hour).Unix(), 10), // 7 days
		StarkKey:          "0x03a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678", // Stark public key
		PositionID:        "12345",                                                     // Position ID
		LimitOrderQuantum: "1000000",                                                   // Quantum for order size
		OraclePrice:       "50000000000",                                               // Oracle price (if applicable)
	}

	signAndDisplay(secretKey, orderParams, "Perpetual futures order: Long BTC-PERP with USDC collateral")
}

func example3(secretKey string) {
	// Create an order with very large amounts (institutional trading)
	orderParams := signature.OrderParams{
		VaultSell:      "999",
		VaultBuy:       "1000",
		AmountSell:     "100000000000000000000",                                    // 100 ETH
		AmountBuy:      "250000000000",                                             // 250,000 USDC
		TokenSell:      "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",              // WETH address (example)
		TokenBuy:       "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",              // USDC address (example)
		Nonce:          "987654321",
		ExpirationTime: strconv.FormatInt(time.Now().Add(48*time.Hour).Unix(), 10), // 48 hours
		StarkKey:       "0x04f1a2b3c4d5e6f7890123456789abcdef0123456789abcdef0123456789abcd",
		PositionID:     "67890",
		LimitOrderQuantum: "10000000",
		OraclePrice:    "2500000000",
	}

	signAndDisplay(secretKey, orderParams, "Large institutional order: Sell 100 ETH for 250,000 USDC")
}

// signAndDisplay signs the order and displays the results
func signAndDisplay(secretKey string, orderParams signature.OrderParams, description string) {
	fmt.Printf("Description: %s\n\n", description)

	// Print order parameters
	fmt.Println("Order Parameters:")
	paramsJSON, _ := json.MarshalIndent(orderParams, "  ", "  ")
	fmt.Printf("  %s\n\n", string(paramsJSON))

	// Sign the L2 order using Pedersen hash
	sig, err := signature.SignL2Order(secretKey, orderParams)
	if err != nil {
		log.Fatalf("Failed to sign L2 order: %v", err)
	}

	// Parse signature components
	result := parseL2Signature(orderParams, sig)

	// Print signature results
	fmt.Println("Signature Result:")
	fmt.Printf("  Full Signature (128 hex): %s\n\n", result.Signature)
	fmt.Printf("  Components:\n")
	fmt.Printf("    R (64 hex): %s\n", result.R)
	fmt.Printf("    S (64 hex): %s\n", result.S)

	// Pretty print as JSON
	fmt.Println("\n  JSON Format:")
	resultJSON, _ := json.MarshalIndent(result, "    ", "  ")
	fmt.Printf("    %s\n", string(resultJSON))

	// Additional information
	fmt.Println("\n  Hash Algorithm: Pedersen Hash")
	fmt.Println("  Curve: Stark Curve")
	fmt.Println("  Signature Format: r||s (128 hex characters)")
}

// parseL2Signature extracts R and S from the signature (128 hex characters)
func parseL2Signature(orderParams signature.OrderParams, sig string) L2OrderSignatureResult {
	if len(sig) != 128 {
		return L2OrderSignatureResult{
			OrderParams: orderParams,
			Signature:   sig,
		}
	}

	return L2OrderSignatureResult{
		OrderParams: orderParams,
		Signature:   sig,
		R:           sig[0:64],
		S:           sig[64:128],
	}
}

// repeat returns a string repeated n times
func repeat(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}
