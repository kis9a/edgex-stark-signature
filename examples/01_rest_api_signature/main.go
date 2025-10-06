package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/kis9a/edgex-stark-signature/pkg/signature"
)

// RESTAPIRequest represents a typical REST API request structure
type RESTAPIRequest struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Timestamp  int64             `json:"timestamp"`
	Parameters map[string]string `json:"parameters"`
}

// SignatureResult represents the signature output
type SignatureResult struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	R         string `json:"r"`
	S         string `json:"s"`
	Y         string `json:"y"`
}

func main() {
	fmt.Println("=== EdgeX Stark Curve REST API Signature Demo ===")
	fmt.Println()

	// Get secret key from environment variable
	secretKey := os.Getenv("EDGEX_SECRET_KEY")
	if secretKey == "" {
		log.Fatal("Error: EDGEX_SECRET_KEY environment variable is not set.\n" +
			"Please set it before running this example:\n" +
			"  export EDGEX_SECRET_KEY=your-secret-key-hex\n" +
			"Or copy .env.example to .env and fill in your credentials.")
	}

	// Example 1: Simple GET request
	fmt.Println("Example 1: Simple GET Request")
	fmt.Println("--------------------------------")
	example1(secretKey)

	fmt.Println("\n" + repeat("=", 60) + "\n")

	// Example 2: POST request with parameters
	fmt.Println("Example 2: POST Request with Parameters")
	fmt.Println("----------------------------------------")
	example2(secretKey)

	fmt.Println("\n" + repeat("=", 60) + "\n")

	// Example 3: Complex request with sorted parameters
	fmt.Println("Example 3: Complex Request with Sorted Parameters")
	fmt.Println("--------------------------------------------------")
	example3(secretKey)
}

func example1(secretKey string) {
	// Create a simple GET request
	request := RESTAPIRequest{
		Method:     "GET",
		Path:       "/api/v1/account/info",
		Timestamp:  time.Now().UnixMilli(),
		Parameters: map[string]string{},
	}

	// Build the message to sign
	message := buildRESTMessage(request)

	// Sign the message
	sig, err := signature.SignRESTMessage(secretKey, message)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}

	// Display results
	result := parseSignature(message, sig)
	printResult(request, result)
}

func example2(secretKey string) {
	// Create a POST request with parameters
	request := RESTAPIRequest{
		Method:    "POST",
		Path:      "/api/v1/orders/create",
		Timestamp: time.Now().UnixMilli(),
		Parameters: map[string]string{
			"symbol":   "BTC-USD",
			"side":     "buy",
			"quantity": "0.5",
			"price":    "45000.00",
		},
	}

	// Build the message to sign
	message := buildRESTMessage(request)

	// Sign the message
	sig, err := signature.SignRESTMessage(secretKey, message)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}

	// Display results
	result := parseSignature(message, sig)
	printResult(request, result)
}

func example3(secretKey string) {
	// Create a complex request demonstrating parameter sorting
	request := RESTAPIRequest{
		Method:    "POST",
		Path:      "/api/v1/trading/limit-order",
		Timestamp: time.Now().UnixMilli(),
		Parameters: map[string]string{
			"nonce":           "123456",
			"token_sell":      "ETH",
			"token_buy":       "USDC",
			"amount_sell":     "1000000000000000000", // 1 ETH in wei
			"amount_buy":      "2500000000",          // 2500 USDC (6 decimals)
			"vault_id_sell":   "1",
			"vault_id_buy":    "2",
			"expiration_time": strconv.FormatInt(time.Now().Add(24*time.Hour).Unix(), 10),
		},
	}

	// Build the message to sign
	message := buildRESTMessage(request)

	// Sign the message
	sig, err := signature.SignRESTMessage(secretKey, message)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}

	// Display results
	result := parseSignature(message, sig)
	printResult(request, result)
}

// buildRESTMessage constructs the canonical message string for signing
// Format: METHOD|PATH|TIMESTAMP|SORTED_PARAMS
func buildRESTMessage(request RESTAPIRequest) string {
	// Sort parameters alphabetically by key
	var sortedParams string
	if len(request.Parameters) > 0 {
		sortedParams = sortAndEncodeParameters(request.Parameters)
	}

	// Construct the message: TIMESTAMP + METHOD + PATH + PARAMS (no separators)
	message := fmt.Sprintf("%d%s%s", request.Timestamp, request.Method, request.Path)
	if sortedParams != "" {
		message += sortedParams
	}

	return message
}

// sortAndEncodeParameters sorts parameters by key and URL-encodes them
func sortAndEncodeParameters(params map[string]string) string {
	// Get sorted keys
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build query string
	values := url.Values{}
	for _, k := range keys {
		values.Add(k, params[k])
	}

	return values.Encode()
}

// parseSignature extracts R, S, Y from the signature (192 hex characters)
func parseSignature(message, sig string) SignatureResult {
	if len(sig) != 192 {
		return SignatureResult{
			Message:   message,
			Signature: sig,
		}
	}

	return SignatureResult{
		Message:   message,
		Signature: sig,
		R:         sig[0:64],
		S:         sig[64:128],
		Y:         sig[128:192],
	}
}

// printResult displays the request and signature in a readable format
func printResult(request RESTAPIRequest, result SignatureResult) {
	// Print request details
	fmt.Println("Request Details:")
	requestJSON, _ := json.MarshalIndent(request, "  ", "  ")
	fmt.Printf("  %s\n\n", string(requestJSON))

	// Print message to sign
	fmt.Println("Message to Sign:")
	fmt.Printf("  %s\n\n", result.Message)

	// Print signature components
	fmt.Println("Signature Result:")
	fmt.Printf("  Full Signature (192 hex): %s\n\n", result.Signature)
	fmt.Printf("  Components:\n")
	fmt.Printf("    R (64 hex): %s\n", result.R)
	fmt.Printf("    S (64 hex): %s\n", result.S)
	fmt.Printf("    Y (64 hex): %s\n", result.Y)

	// Pretty print as JSON
	fmt.Println("\n  JSON Format:")
	resultJSON, _ := json.MarshalIndent(result, "    ", "  ")
	fmt.Printf("    %s\n", string(resultJSON))
}

// repeat returns a string repeated n times
func repeat(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}
