package signature

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	starkcurve "github.com/consensys/gnark-crypto/ecc/stark-curve"
	"github.com/consensys/gnark-crypto/ecc/stark-curve/ecdsa"
	"github.com/consensys/gnark-crypto/ecc/stark-curve/fp"
	"github.com/consensys/gnark-crypto/ecc/stark-curve/fr"
	pedersen "github.com/consensys/gnark-crypto/ecc/stark-curve/pedersen-hash"
	"golang.org/x/crypto/sha3"
)

// K_MODULUS is the order of the Stark curve group
// 0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f
var K_MODULUS = new(big.Int)

// FIELD_PRIME is the field prime for L2 operations
// 0x800000000000011000000000000000000000000000000000000000000000001
var FIELD_PRIME = new(big.Int)

func init() {
	K_MODULUS.SetString("0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f", 16)
	FIELD_PRIME.SetString("0800000000000011000000000000000000000000000000000000000000000001", 16)
}

// OrderParams represents the parameters for L2 order signing
type OrderParams struct {
	VaultSell          string
	VaultBuy           string
	AmountSell         string
	AmountBuy          string
	TokenSell          string
	TokenBuy           string
	Nonce              string
	ExpirationTime     string
	StarkKey           string
	PositionID         string
	LimitOrderQuantum  string
	OraclePrice        string
}

// SignRESTMessage signs a message using Keccak-256 hash and Stark curve ECDSA
// Returns a signature in r||s||Y format (192 hex characters)
func SignRESTMessage(secretKey, message string) (string, error) {
	if secretKey == "" {
		return "", errors.New("secret key cannot be empty")
	}
	if message == "" {
		return "", errors.New("message cannot be empty")
	}

	// Parse secret key
	secretKeyBytes, err := hex.DecodeString(secretKey)
	if err != nil {
		return "", fmt.Errorf("invalid secret key hex: %w", err)
	}

	privKey := new(big.Int).SetBytes(secretKeyBytes)

	// Validate private key is non-zero and less than K_MODULUS
	if privKey.Sign() == 0 {
		return "", errors.New("secret key cannot be zero")
	}
	if privKey.Cmp(K_MODULUS) >= 0 {
		return "", errors.New("secret key must be less than K_MODULUS")
	}

	// Apply Keccak-256 hash (Ethereum-compatible)
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte(message))
	hashBytes := hasher.Sum(nil)

	// Apply modulo K_MODULUS
	hashInt := new(big.Int).SetBytes(hashBytes)
	hashInt.Mod(hashInt, K_MODULUS)

	// Generate ECDSA signature
	r, s, err := signStarkCurve(privKey, hashInt)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	// Compute Y coordinate (public key Y coordinate)
	// For Y, we need to compute the public key from the private key
	// Y is derived from the public key point
	pubKey, err := computePublicKey(privKey)
	if err != nil {
		return "", fmt.Errorf("failed to compute public key: %w", err)
	}

	// Format: r||s||Y (64 + 64 + 64 hex chars = 192 chars)
	rHex := fmt.Sprintf("%064x", r)
	sHex := fmt.Sprintf("%064x", s)
	yHex := fmt.Sprintf("%064x", pubKey)

	return rHex + sHex + yHex, nil
}

// SignL2Order signs an L2 order using Pedersen hash
// Returns a signature in r||s format (128 hex characters)
func SignL2Order(secretKey string, orderParams OrderParams) (string, error) {
	if secretKey == "" {
		return "", errors.New("secret key cannot be empty")
	}

	// Parse secret key
	secretKeyBytes, err := hex.DecodeString(secretKey)
	if err != nil {
		return "", fmt.Errorf("invalid secret key hex: %w", err)
	}

	privKey := new(big.Int).SetBytes(secretKeyBytes)

	// Validate private key
	if privKey.Sign() == 0 {
		return "", errors.New("secret key cannot be zero")
	}
	if privKey.Cmp(K_MODULUS) >= 0 {
		return "", errors.New("secret key must be less than K_MODULUS")
	}

	// Compute Pedersen hash of order parameters
	hash, err := computeOrderHash(orderParams)
	if err != nil {
		return "", fmt.Errorf("failed to compute order hash: %w", err)
	}

	// Apply modulo FIELD_PRIME
	hashInt := new(big.Int).SetBytes(hash)
	hashInt.Mod(hashInt, FIELD_PRIME)

	// Generate ECDSA signature
	r, s, err := signStarkCurve(privKey, hashInt)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	// Format: r||s (64 + 64 hex chars = 128 chars)
	rHex := fmt.Sprintf("%064x", r)
	sHex := fmt.Sprintf("%064x", s)

	return rHex + sHex, nil
}

// signStarkCurve performs ECDSA signing on the Stark curve
func signStarkCurve(privKey *big.Int, hash *big.Int) (*big.Int, *big.Int, error) {
	// Convert hash to bytes for signing
	hashBytes := hash.Bytes()
	if len(hashBytes) < 32 {
		// Pad with zeros on the left
		padded := make([]byte, 32)
		copy(padded[32-len(hashBytes):], hashBytes)
		hashBytes = padded
	}

	// Convert private key to bytes (big endian, 32 bytes)
	scalarBytes := make([]byte, 32)
	privKey.FillBytes(scalarBytes)

	// Create fr.Element from scalar
	var scalar fr.Element
	scalar.SetBytes(scalarBytes)

	// Compute public key: pubKey = scalar * G
	var pubKey starkcurve.G1Affine
	pubKey.ScalarMultiplicationBase(scalar.BigInt(new(big.Int)))

	// Create private key bytes: pubKey.Bytes() || scalar (32 + 32 = 64 bytes)
	pubKeyBytes := pubKey.Bytes()
	fullPrivKeyBytes := append(pubKeyBytes[:], scalarBytes...)

	// Create ECDSA private key
	privateKey := new(ecdsa.PrivateKey)
	_, err := privateKey.SetBytes(fullPrivKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to set private key: %w", err)
	}

	// Sign the hash (using sha3 Keccak256 as the hash function)
	hasher := sha3.NewLegacyKeccak256()
	sigBytes, err := privateKey.Sign(hashBytes, hasher)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDSA sign failed: %w", err)
	}

	// Parse signature (R || S format, each 32 bytes)
	if len(sigBytes) < 64 {
		return nil, nil, fmt.Errorf("invalid signature length: %d", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:64])

	return r, s, nil
}

// computePublicKey computes the Y coordinate of the public key
func computePublicKey(privKey *big.Int) (*big.Int, error) {
	// Convert private key to bytes (big endian, 32 bytes)
	scalarBytes := make([]byte, 32)
	privKey.FillBytes(scalarBytes)

	// Create fr.Element from scalar
	var scalar fr.Element
	scalar.SetBytes(scalarBytes)

	// Compute public key: pubKey = scalar * G
	var pubKey starkcurve.G1Affine
	pubKey.ScalarMultiplicationBase(scalar.BigInt(new(big.Int)))

	// Extract Y coordinate
	// Note: For Stark curve, the compressed format only stores X with a parity bit
	// We need to get the full Y coordinate from the affine point
	y := pubKey.Y.BigInt(new(big.Int))

	return y, nil
}

// parseHexString parses a hex string with optional 0x prefix
func parseHexString(s string) (*big.Int, bool) {
	// Remove 0x prefix if present
	if len(s) > 2 && s[0:2] == "0x" {
		s = s[2:]
	}
	return new(big.Int).SetString(s, 16)
}

// computeOrderHash computes the Pedersen hash of order parameters
func computeOrderHash(params OrderParams) ([]byte, error) {
	// Parse all parameters to big.Int
	vaultSell, ok := new(big.Int).SetString(params.VaultSell, 10)
	if !ok {
		return nil, errors.New("invalid VaultSell")
	}
	vaultBuy, ok := new(big.Int).SetString(params.VaultBuy, 10)
	if !ok {
		return nil, errors.New("invalid VaultBuy")
	}
	amountSell, ok := new(big.Int).SetString(params.AmountSell, 10)
	if !ok {
		return nil, errors.New("invalid AmountSell")
	}
	amountBuy, ok := new(big.Int).SetString(params.AmountBuy, 10)
	if !ok {
		return nil, errors.New("invalid AmountBuy")
	}
	tokenSell, ok := parseHexString(params.TokenSell)
	if !ok {
		return nil, errors.New("invalid TokenSell")
	}
	tokenBuy, ok := parseHexString(params.TokenBuy)
	if !ok {
		return nil, errors.New("invalid TokenBuy")
	}
	nonce, ok := new(big.Int).SetString(params.Nonce, 10)
	if !ok {
		return nil, errors.New("invalid Nonce")
	}
	expirationTime, ok := new(big.Int).SetString(params.ExpirationTime, 10)
	if !ok {
		return nil, errors.New("invalid ExpirationTime")
	}

	// Combine all parameters for Pedersen hash
	// The exact structure depends on the protocol specification
	// Here we concatenate all values
	data := make([]*big.Int, 0)
	data = append(data, vaultSell, vaultBuy, amountSell, amountBuy, tokenSell, tokenBuy, nonce, expirationTime)

	// Compute Pedersen hash
	hash, err := pedersenHashMany(data)
	if err != nil {
		return nil, fmt.Errorf("Pedersen hash failed: %w", err)
	}

	return hash, nil
}

// pedersenHashMany computes Pedersen hash of multiple big.Int values
func pedersenHashMany(values []*big.Int) ([]byte, error) {
	if len(values) == 0 {
		return nil, errors.New("no values to hash")
	}

	if len(values) < 2 {
		return nil, errors.New("need at least 2 elements for Pedersen hash")
	}

	// Use Pedersen hash from gnark-crypto
	// PedersenArray accepts variadic fp.Element parameters
	elements := make([]*fp.Element, len(values))
	for i, v := range values {
		elem := new(fp.Element)
		elem.SetBigInt(v)
		elements[i] = elem
	}

	// Call PedersenArray
	result := pedersen.PedersenArray(elements...)

	// Convert result to bytes
	resultBytes := result.Bytes()
	return resultBytes[:], nil
}
