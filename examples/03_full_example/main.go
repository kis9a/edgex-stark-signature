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

// API Configuration
const (
	API_BASE_URL = "https://api.edgex.exchange"
	API_VERSION  = "v1"
)

// EdgeXAPIClient represents an API client with signature capabilities
type EdgeXAPIClient struct {
	SecretKey  string
	BaseURL    string
	APIVersion string
}

// HTTPRequest represents a complete HTTP request with headers
type HTTPRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// NewEdgeXAPIClient creates a new API client instance
func NewEdgeXAPIClient(secretKey string) *EdgeXAPIClient {
	return &EdgeXAPIClient{
		SecretKey:  secretKey,
		BaseURL:    API_BASE_URL,
		APIVersion: API_VERSION,
	}
}

func main() {
	fmt.Println("=== EdgeX Full API Client Integration Example ===")
	fmt.Println()

	// Get secret key from environment variable
	secretKey := os.Getenv("EDGEX_SECRET_KEY")
	if secretKey == "" {
		log.Fatal("Error: EDGEX_SECRET_KEY environment variable is not set.\n" +
			"Please set it before running this example:\n" +
			"  export EDGEX_SECRET_KEY=your-secret-key-hex\n" +
			"Or copy .env.example to .env and fill in your credentials.")
	}

	// Initialize the API client
	client := NewEdgeXAPIClient(secretKey)

	// Example 1: Get account balance (REST signature)
	fmt.Println("Example 1: Get Account Balance")
	fmt.Println("===============================")
	if err := exampleGetAccountBalance(client); err != nil {
		log.Printf("Error in example 1: %v\n", err)
	}

	fmt.Println("\n" + repeat("=", 80) + "\n")

	// Example 2: Create limit order (both REST and L2 signatures)
	fmt.Println("Example 2: Create Limit Order")
	fmt.Println("==============================")
	if err := exampleCreateLimitOrder(client); err != nil {
		log.Printf("Error in example 2: %v\n", err)
	}

	fmt.Println("\n" + repeat("=", 80) + "\n")

	// Example 3: Cancel order (REST signature)
	fmt.Println("Example 3: Cancel Order")
	fmt.Println("=======================")
	if err := exampleCancelOrder(client); err != nil {
		log.Printf("Error in example 3: %v\n", err)
	}

	fmt.Println("\n" + repeat("=", 80) + "\n")

	// Example 4: Submit L2 order directly (L2 signature only)
	fmt.Println("Example 4: Submit L2 Order")
	fmt.Println("==========================")
	if err := exampleSubmitL2Order(client); err != nil {
		log.Printf("Error in example 4: %v\n", err)
	}
}

// exampleGetAccountBalance demonstrates a simple GET request with REST signature
func exampleGetAccountBalance(client *EdgeXAPIClient) error {
	fmt.Println("Description: Retrieve account balance and open positions")
	fmt.Println()

	// Build request parameters
	method := "GET"
	path := fmt.Sprintf("/api/%s/account/balance", client.APIVersion)
	timestamp := time.Now().UnixMilli()
	params := map[string]string{
		"account_id": "0x1234567890abcdef",
	}

	// Sign the request
	message := buildSignatureMessage(method, path, timestamp, params)
	sig, err := signature.SignRESTMessage(client.SecretKey, message)
	if err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}

	// Build HTTP request
	fullURL := buildURL(client.BaseURL, path, params)
	headers := buildAuthHeaders(sig, timestamp)
	request := HTTPRequest{
		Method:  method,
		URL:     fullURL,
		Headers: headers,
		Body:    "",
	}

	// Display the request
	displayHTTPRequest(request, message, sig)

	fmt.Println("\nNote: This is a demonstration. In a real application, you would send this request using an HTTP client.")

	return nil
}

// exampleCreateLimitOrder demonstrates a POST request requiring both REST and L2 signatures
func exampleCreateLimitOrder(client *EdgeXAPIClient) error {
	fmt.Println("Description: Create a limit order to sell 1 ETH at 2500 USDC")
	fmt.Println()

	// Step 1: Prepare L2 order parameters
	orderParams := signature.OrderParams{
		VaultSell:      "1",
		VaultBuy:       "2",
		AmountSell:     "1000000000000000000", // 1 ETH
		AmountBuy:      "2500000000",          // 2500 USDC
		TokenSell:      "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7", // ETH on StarkNet
		TokenBuy:       "0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8", // USDC on StarkNet
		Nonce:          strconv.FormatInt(time.Now().Unix(), 10),
		ExpirationTime: strconv.FormatInt(time.Now().Add(24*time.Hour).Unix(), 10),
		StarkKey:       "0x03a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef12345678",
		PositionID:     "",
		LimitOrderQuantum: "",
		OraclePrice:    "",
	}

	// Sign the L2 order
	l2Sig, err := signature.SignL2Order(client.SecretKey, orderParams)
	if err != nil {
		return fmt.Errorf("failed to sign L2 order: %w", err)
	}

	fmt.Println("L2 Order Signature:")
	fmt.Printf("  Signature: %s\n", l2Sig)
	fmt.Printf("  R: %s\n", l2Sig[0:64])
	fmt.Printf("  S: %s\n", l2Sig[64:128])
	fmt.Println()

	// Step 2: Prepare REST API request
	method := "POST"
	path := fmt.Sprintf("/api/%s/orders/limit", client.APIVersion)
	timestamp := time.Now().UnixMilli()

	// Request body (would be JSON in real application)
	requestBody := map[string]interface{}{
		"vault_sell":      orderParams.VaultSell,
		"vault_buy":       orderParams.VaultBuy,
		"amount_sell":     orderParams.AmountSell,
		"amount_buy":      orderParams.AmountBuy,
		"token_sell":      orderParams.TokenSell,
		"token_buy":       orderParams.TokenBuy,
		"nonce":           orderParams.Nonce,
		"expiration_time": orderParams.ExpirationTime,
		"stark_key":       orderParams.StarkKey,
		"l2_signature":    l2Sig,
	}

	bodyJSON, _ := json.Marshal(requestBody)

	// Create message for REST signature (includes body hash for POST requests)
	restParams := map[string]string{
		"body_hash": hashJSON(string(bodyJSON)),
	}
	message := buildSignatureMessage(method, path, timestamp, restParams)

	// Sign the REST request
	restSig, err := signature.SignRESTMessage(client.SecretKey, message)
	if err != nil {
		return fmt.Errorf("failed to sign REST request: %w", err)
	}

	fmt.Println("REST API Signature:")
	fmt.Printf("  Signature: %s\n", restSig)
	fmt.Printf("  R: %s\n", restSig[0:64])
	fmt.Printf("  S: %s\n", restSig[64:128])
	fmt.Printf("  Y: %s\n", restSig[128:192])
	fmt.Println()

	// Build HTTP request
	fullURL := client.BaseURL + path
	headers := buildAuthHeaders(restSig, timestamp)
	headers["Content-Type"] = "application/json"

	request := HTTPRequest{
		Method:  method,
		URL:     fullURL,
		Headers: headers,
		Body:    string(bodyJSON),
	}

	// Display the request
	displayHTTPRequest(request, message, restSig)

	fmt.Println("\nNote: This request includes both L2 signature (for order validation) and REST signature (for API authentication).")

	return nil
}

// exampleCancelOrder demonstrates canceling an existing order
func exampleCancelOrder(client *EdgeXAPIClient) error {
	fmt.Println("Description: Cancel an existing order by ID")
	fmt.Println()

	method := "DELETE"
	path := fmt.Sprintf("/api/%s/orders/cancel", client.APIVersion)
	timestamp := time.Now().UnixMilli()
	params := map[string]string{
		"order_id": "0xabcdef1234567890",
	}

	// Sign the request
	message := buildSignatureMessage(method, path, timestamp, params)
	sig, err := signature.SignRESTMessage(client.SecretKey, message)
	if err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}

	// Build HTTP request
	fullURL := buildURL(client.BaseURL, path, params)
	headers := buildAuthHeaders(sig, timestamp)
	request := HTTPRequest{
		Method:  method,
		URL:     fullURL,
		Headers: headers,
		Body:    "",
	}

	// Display the request
	displayHTTPRequest(request, message, sig)

	return nil
}

// exampleSubmitL2Order demonstrates submitting an L2 order directly to the StarkEx layer
func exampleSubmitL2Order(client *EdgeXAPIClient) error {
	fmt.Println("Description: Submit L2 order directly to StarkEx settlement layer")
	fmt.Println()

	// Prepare L2 order for perpetual trading
	orderParams := signature.OrderParams{
		VaultSell:         "100",
		VaultBuy:          "101",
		AmountSell:        "5000000000",  // Position size
		AmountBuy:         "250000000000", // Collateral
		TokenSell:         "0x4254431234567890abcdef1234567890abcdef1234567890abcdef", // BTC synthetic (valid hex)
		TokenBuy:          "0x555344431234567890abcdef1234567890abcdef1234567890abcd", // USDC collateral (valid hex)
		Nonce:             "424242",
		ExpirationTime:    strconv.FormatInt(time.Now().Add(7*24*time.Hour).Unix(), 10),
		StarkKey:          "0x04f1a2b3c4d5e6f7890123456789abcdef0123456789abcdef0123456789abcd",
		PositionID:        "98765",
		LimitOrderQuantum: "1000000",
		OraclePrice:       "50000000000",
	}

	// Sign the L2 order
	l2Sig, err := signature.SignL2Order(client.SecretKey, orderParams)
	if err != nil {
		return fmt.Errorf("failed to sign L2 order: %w", err)
	}

	fmt.Println("L2 Order Parameters:")
	paramsJSON, _ := json.MarshalIndent(orderParams, "  ", "  ")
	fmt.Printf("  %s\n\n", string(paramsJSON))

	fmt.Println("L2 Signature:")
	fmt.Printf("  Full Signature: %s\n", l2Sig)
	fmt.Printf("  R: %s\n", l2Sig[0:64])
	fmt.Printf("  S: %s\n", l2Sig[64:128])
	fmt.Println()

	// In a real application, this would be submitted to the StarkEx contract
	fmt.Println("Submission Details:")
	fmt.Println("  Target: StarkEx Settlement Contract")
	fmt.Println("  Method: submitOrder()")
	fmt.Println("  Parameters: order_params + signature")
	fmt.Println("\nNote: L2 orders are submitted directly to the StarkEx smart contract.")

	return nil
}

// buildSignatureMessage constructs the canonical message for REST signature
func buildSignatureMessage(method, path string, timestamp int64, params map[string]string) string {
	sortedParams := ""
	if len(params) > 0 {
		sortedParams = sortAndEncodeParameters(params)
	}

	// Format: TIMESTAMP + METHOD + PATH + PARAMS (no separators)
	message := fmt.Sprintf("%d%s%s", timestamp, method, path)
	if sortedParams != "" {
		message += sortedParams
	}
	return message
}

// sortAndEncodeParameters sorts and URL-encodes parameters
func sortAndEncodeParameters(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	values := url.Values{}
	for _, k := range keys {
		values.Add(k, params[k])
	}

	return values.Encode()
}

// buildURL constructs a full URL with query parameters
func buildURL(baseURL, path string, params map[string]string) string {
	fullURL := baseURL + path
	if len(params) > 0 {
		fullURL += "?" + sortAndEncodeParameters(params)
	}
	return fullURL
}

// buildAuthHeaders creates authentication headers with signature
func buildAuthHeaders(signature string, timestamp int64) map[string]string {
	return map[string]string{
		"X-edgeX-Api-Signature": signature,
		"X-edgeX-Api-Timestamp": strconv.FormatInt(timestamp, 10),
		"X-edgeX-Api-Key":       "your-api-key-here", // In production, use actual API key
	}
}

// hashJSON creates a simple hash of JSON body (in production, use proper hash function)
func hashJSON(body string) string {
	// This is a simplified example. In production, you would use:
	// 1. Canonical JSON serialization
	// 2. Keccak-256 or SHA-256 hash
	// 3. Hex encoding
	return fmt.Sprintf("hash_%d", len(body))
}

// displayHTTPRequest displays a formatted HTTP request
func displayHTTPRequest(request HTTPRequest, message, signature string) {
	fmt.Println("HTTP Request Details:")
	fmt.Println("---------------------")
	fmt.Printf("Method:  %s\n", request.Method)
	fmt.Printf("URL:     %s\n\n", request.URL)

	fmt.Println("Headers:")
	for k, v := range request.Headers {
		fmt.Printf("  %s: %s\n", k, v)
	}

	if request.Body != "" {
		fmt.Println("\nBody:")
		// Pretty print JSON if possible
		var bodyMap map[string]interface{}
		if err := json.Unmarshal([]byte(request.Body), &bodyMap); err == nil {
			bodyJSON, _ := json.MarshalIndent(bodyMap, "  ", "  ")
			fmt.Printf("  %s\n", string(bodyJSON))
		} else {
			fmt.Printf("  %s\n", request.Body)
		}
	}

	fmt.Println("\nSignature Details:")
	fmt.Println("------------------")
	fmt.Printf("Message: %s\n", message)
	fmt.Printf("Signature: %s\n", signature)

	// Example curl command
	fmt.Println("\nEquivalent cURL Command:")
	fmt.Println("------------------------")
	curlCmd := fmt.Sprintf("curl -X %s '%s'", request.Method, request.URL)
	for k, v := range request.Headers {
		curlCmd += fmt.Sprintf(" \\\n  -H '%s: %s'", k, v)
	}
	if request.Body != "" {
		curlCmd += fmt.Sprintf(" \\\n  -d '%s'", request.Body)
	}
	fmt.Println(curlCmd)
}

// repeat returns a string repeated n times
func repeat(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}
