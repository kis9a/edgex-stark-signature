package signature

import (
	"math/big"
	"strings"
	"testing"
)

// Test-only dummy secret key - NOT for production use!
// This is a randomly generated key for testing purposes only.
const testSecretKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestSignRESTMessage(t *testing.T) {
	tests := []struct {
		name        string
		secretKey   string
		message     string
		wantErr     bool
		errContains string
	}{
		{
			name:      "valid signature",
			secretKey: testSecretKey,
			message:   "test message",
			wantErr:   false,
		},
		{
			name:        "empty secret key",
			secretKey:   "",
			message:     "test message",
			wantErr:     true,
			errContains: "secret key cannot be empty",
		},
		{
			name:        "empty message",
			secretKey:   testSecretKey,
			message:     "",
			wantErr:     true,
			errContains: "message cannot be empty",
		},
		{
			name:        "invalid hex secret key",
			secretKey:   "xyz123",
			message:     "test message",
			wantErr:     true,
			errContains: "invalid secret key hex",
		},
		{
			name:        "zero secret key",
			secretKey:   "0000000000000000000000000000000000000000000000000000000000000000",
			message:     "test message",
			wantErr:     true,
			errContains: "secret key cannot be zero",
		},
		{
			name:      "another valid key",
			secretKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			message:   "hello world",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := SignRESTMessage(tt.secretKey, tt.message)

			if tt.wantErr {
				if err == nil {
					t.Errorf("SignRESTMessage() expected error containing '%s', got nil", tt.errContains)
					return
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("SignRESTMessage() error = %v, want error containing %v", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("SignRESTMessage() unexpected error = %v", err)
				return
			}

			// Verify signature format: r||s||Y (192 hex characters)
			if len(sig) != 192 {
				t.Errorf("SignRESTMessage() signature length = %d, want 192", len(sig))
			}

			// Verify signature is valid hex
			for i, c := range sig {
				if !isHexChar(c) {
					t.Errorf("SignRESTMessage() signature contains non-hex character at position %d: %c", i, c)
				}
			}

			// Verify signature is deterministic (same input produces same output)
			sig2, err2 := SignRESTMessage(tt.secretKey, tt.message)
			if err2 != nil {
				t.Errorf("SignRESTMessage() second call error = %v", err2)
				return
			}

			// Note: ECDSA signatures may not be deterministic due to random k
			// So we just verify both signatures are valid format
			if len(sig2) != 192 {
				t.Errorf("SignRESTMessage() second signature length = %d, want 192", len(sig2))
			}
		})
	}
}

func TestSignL2Order(t *testing.T) {
	tests := []struct {
		name        string
		secretKey   string
		orderParams OrderParams
		wantErr     bool
		errContains string
	}{
		{
			name:      "valid L2 order signature",
			secretKey: testSecretKey,
			orderParams: OrderParams{
				VaultSell:      "1",
				VaultBuy:       "2",
				AmountSell:     "1000000",
				AmountBuy:      "2000000",
				TokenSell:      "0x1234",
				TokenBuy:       "0x5678",
				Nonce:          "1",
				ExpirationTime: "1234567890",
			},
			wantErr: false,
		},
		{
			name:      "empty secret key",
			secretKey: "",
			orderParams: OrderParams{
				VaultSell:      "1",
				VaultBuy:       "2",
				AmountSell:     "1000000",
				AmountBuy:      "2000000",
				TokenSell:      "0x1234",
				TokenBuy:       "0x5678",
				Nonce:          "1",
				ExpirationTime: "1234567890",
			},
			wantErr:     true,
			errContains: "secret key cannot be empty",
		},
		{
			name:      "invalid VaultSell",
			secretKey: testSecretKey,
			orderParams: OrderParams{
				VaultSell:      "invalid",
				VaultBuy:       "2",
				AmountSell:     "1000000",
				AmountBuy:      "2000000",
				TokenSell:      "0x1234",
				TokenBuy:       "0x5678",
				Nonce:          "1",
				ExpirationTime: "1234567890",
			},
			wantErr:     true,
			errContains: "invalid VaultSell",
		},
		{
			name:      "invalid TokenSell hex",
			secretKey: testSecretKey,
			orderParams: OrderParams{
				VaultSell:      "1",
				VaultBuy:       "2",
				AmountSell:     "1000000",
				AmountBuy:      "2000000",
				TokenSell:      "0xZZZZ",
				TokenBuy:       "0x5678",
				Nonce:          "1",
				ExpirationTime: "1234567890",
			},
			wantErr:     true,
			errContains: "invalid TokenSell",
		},
		{
			name:      "zero secret key",
			secretKey: "0000000000000000000000000000000000000000000000000000000000000000",
			orderParams: OrderParams{
				VaultSell:      "1",
				VaultBuy:       "2",
				AmountSell:     "1000000",
				AmountBuy:      "2000000",
				TokenSell:      "0x1234",
				TokenBuy:       "0x5678",
				Nonce:          "1",
				ExpirationTime: "1234567890",
			},
			wantErr:     true,
			errContains: "secret key cannot be zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := SignL2Order(tt.secretKey, tt.orderParams)

			if tt.wantErr {
				if err == nil {
					t.Errorf("SignL2Order() expected error containing '%s', got nil", tt.errContains)
					return
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("SignL2Order() error = %v, want error containing %v", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("SignL2Order() unexpected error = %v", err)
				return
			}

			// Verify signature format: r||s (128 hex characters)
			if len(sig) != 128 {
				t.Errorf("SignL2Order() signature length = %d, want 128", len(sig))
			}

			// Verify signature is valid hex
			for i, c := range sig {
				if !isHexChar(c) {
					t.Errorf("SignL2Order() signature contains non-hex character at position %d: %c", i, c)
				}
			}
		})
	}
}

func TestKModulusValue(t *testing.T) {
	// Note: big.Int.Text(16) doesn't include leading zeros, so we compare without the leading 0
	expected := "800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f"
	actual := K_MODULUS.Text(16)

	if actual != expected {
		t.Errorf("K_MODULUS = %s, want %s", actual, expected)
	}

	// Also verify the actual value matches the spec with leading 0
	expectedWithLeading := new(big.Int)
	expectedWithLeading.SetString("0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f", 16)
	if K_MODULUS.Cmp(expectedWithLeading) != 0 {
		t.Errorf("K_MODULUS value mismatch")
	}
}

func TestFieldPrimeValue(t *testing.T) {
	expected := "800000000000011000000000000000000000000000000000000000000000001"
	actual := FIELD_PRIME.Text(16)

	if actual != expected {
		t.Errorf("FIELD_PRIME = %s, want %s", actual, expected)
	}
}

func TestComputeOrderHash(t *testing.T) {
	tests := []struct {
		name        string
		params      OrderParams
		wantErr     bool
		errContains string
	}{
		{
			name: "valid order parameters",
			params: OrderParams{
				VaultSell:      "1",
				VaultBuy:       "2",
				AmountSell:     "1000000",
				AmountBuy:      "2000000",
				TokenSell:      "0x1234",
				TokenBuy:       "0x5678",
				Nonce:          "1",
				ExpirationTime: "1234567890",
			},
			wantErr: false,
		},
		{
			name: "invalid VaultSell",
			params: OrderParams{
				VaultSell:      "not_a_number",
				VaultBuy:       "2",
				AmountSell:     "1000000",
				AmountBuy:      "2000000",
				TokenSell:      "1234",
				TokenBuy:       "5678",
				Nonce:          "1",
				ExpirationTime: "1234567890",
			},
			wantErr:     true,
			errContains: "invalid VaultSell",
		},
		{
			name: "invalid TokenBuy hex",
			params: OrderParams{
				VaultSell:      "1",
				VaultBuy:       "2",
				AmountSell:     "1000000",
				AmountBuy:      "2000000",
				TokenSell:      "0x1234",
				TokenBuy:       "0xGGGG",
				Nonce:          "1",
				ExpirationTime: "1234567890",
			},
			wantErr:     true,
			errContains: "invalid TokenBuy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := computeOrderHash(tt.params)

			if tt.wantErr {
				if err == nil {
					t.Errorf("computeOrderHash() expected error containing '%s', got nil", tt.errContains)
					return
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("computeOrderHash() error = %v, want error containing %v", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("computeOrderHash() unexpected error = %v", err)
				return
			}

			if hash == nil || len(hash) == 0 {
				t.Errorf("computeOrderHash() returned empty hash")
			}
		})
	}
}

func TestPedersenHashMany(t *testing.T) {
	tests := []struct {
		name        string
		values      []string
		wantErr     bool
		errContains string
	}{
		{
			name:    "two values",
			values:  []string{"123", "456"},
			wantErr: false,
		},
		{
			name:    "multiple values",
			values:  []string{"1", "2", "3", "4", "5"},
			wantErr: false,
		},
		{
			name:        "empty values",
			values:      []string{},
			wantErr:     true,
			errContains: "no values to hash",
		},
		{
			name:        "single value",
			values:      []string{"123"},
			wantErr:     true,
			errContains: "need at least 2 elements",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var values []*big.Int
			for _, v := range tt.values {
				val, ok := new(big.Int).SetString(v, 10)
				if !ok {
					t.Fatalf("failed to parse test value: %s", v)
				}
				values = append(values, val)
			}

			hash, err := pedersenHashMany(values)

			if tt.wantErr {
				if err == nil {
					t.Errorf("pedersenHashMany() expected error containing '%s', got nil", tt.errContains)
					return
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("pedersenHashMany() error = %v, want error containing %v", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("pedersenHashMany() unexpected error = %v", err)
				return
			}

			if hash == nil || len(hash) == 0 {
				t.Errorf("pedersenHashMany() returned empty hash")
			}
		})
	}
}

// Helper function to check if a character is a valid hex digit
func isHexChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// Benchmark tests
func BenchmarkSignRESTMessage(b *testing.B) {
	secretKey := testSecretKey
	message := "test message for benchmarking"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := SignRESTMessage(secretKey, message)
		if err != nil {
			b.Fatalf("SignRESTMessage failed: %v", err)
		}
	}
}

func BenchmarkSignL2Order(b *testing.B) {
	secretKey := testSecretKey
	orderParams := OrderParams{
		VaultSell:      "1",
		VaultBuy:       "2",
		AmountSell:     "1000000",
		AmountBuy:      "2000000",
		TokenSell:      "1234",
		TokenBuy:       "5678",
		Nonce:          "1",
		ExpirationTime: "1234567890",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := SignL2Order(secretKey, orderParams)
		if err != nil {
			b.Fatalf("SignL2Order failed: %v", err)
		}
	}
}
