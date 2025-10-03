# EdgeX Stark Curve Signature

Go implementation of EdgeX Exchange API authentication using Stark curve ECDSA signatures.

## Features

- **REST API Signature**: Keccak-256 hash with Stark curve ECDSA (192-character signature)
- **L2 Order Signature**: Pedersen hash with Stark curve ECDSA (128-character signature)
- **StarkEx L2 Compatible**: Full compatibility with StarkEx settlement layer
- **Production Ready**: Comprehensive error handling and validation

## Installation

```bash
go get github.com/kis9a/edgex-stark-signature
```

## Setup

**Important**: Never commit your secret keys to version control!

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Edit `.env` and add your EdgeX secret key:
```bash
EDGEX_SECRET_KEY=your-secret-key-hex-here
```

3. Load the environment variables:
```bash
export $(cat .env | xargs)
# or
source .env  # if using bash/zsh
```

## Usage

### REST API Signature

Used for HTTP API authentication. Message format: `METHOD|PATH|TIMESTAMP|PARAMS`

```go
import "github.com/kis9a/edgex-stark-signature/pkg/signature"

secretKey := "your-secret-key-hex"
message := "GET|/api/v1/account/info|1234567890|"

sig, err := signature.SignRESTMessage(secretKey, message)
if err != nil {
    panic(err)
}

fmt.Printf("Signature: %s\n", sig) // 192 hex characters (r||s||Y)
```

**Signature format**: `r||s||Y` (64 + 64 + 64 hex characters = 192 total)
- Uses **Keccak-256** hash
- Applies **K_MODULUS** (EC group order) modular reduction

### L2 Order Signature

Used for StarkEx Layer 2 order submission.

```go
import "github.com/kis9a/edgex-stark-signature/pkg/signature"

secretKey := "your-secret-key-hex"

orderParams := signature.OrderParams{
    VaultSell:      "1",
    VaultBuy:       "2",
    AmountSell:     "1000000000000000000",
    AmountBuy:      "2500000000",
    TokenSell:      "0x1234",
    TokenBuy:       "0x5678",
    Nonce:          "1",
    ExpirationTime: "1234567890",
}

sig, err := signature.SignL2Order(secretKey, orderParams)
if err != nil {
    panic(err)
}

fmt.Printf("Signature: %s\n", sig) // 128 hex characters (r||s)
```

**Signature format**: `r||s` (64 + 64 hex characters = 128 total)
- Uses **Pedersen Hash**
- Applies **FIELD_PRIME** (field prime) modular reduction

## Key Differences

| Aspect | REST Signature | L2 Signature |
|--------|---------------|--------------|
| Hash Function | Keccak-256 | Pedersen Hash |
| Modulus | K_MODULUS (group order) | FIELD_PRIME (field prime) |
| Format | r\|\|s\|\|Y (192 chars) | r\|\|s (128 chars) |
| Purpose | API authentication | L2 order validation |

## Important Constants

```go
// K_MODULUS: Stark curve group order (for REST signatures)
K_MODULUS = 0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f

// FIELD_PRIME: Stark curve field prime (for L2 signatures)
FIELD_PRIME = 0x0800000000000011000000000000000000000000000000000000000000000001
```

## Examples

Make sure you've set the `EDGEX_SECRET_KEY` environment variable before running examples:

```bash
export EDGEX_SECRET_KEY=your-secret-key-hex

go run examples/01_rest_api_signature/main.go
go run examples/02_l2_order_signature/main.go
go run examples/03_full_example/main.go
```

Or use `.env` file:
```bash
# After setting up .env file
export $(cat .env | xargs)
go run examples/01_rest_api_signature/main.go
```

## Testing

```bash
go test ./pkg/signature/...
```

## Troubleshooting

### 401 Authentication Error

**Problem**: Signature verification fails with 401 error

**Common causes**:
1. Missing K_MODULUS/FIELD_PRIME modular reduction
2. Incorrect message format (check delimiter and parameter order)
3. Timestamp drift (ensure NTP synchronization within 30 seconds)

### Invalid Signature Length

**Problem**: Signature is not 192/128 characters

**Solution**: Ensure proper hex padding (use `%064x` format for each component)

## Documentation

- [EdgeX API Documentation](https://edgex-1.gitbook.io/edgex-documentation/api/authentication)
- [Stark Curve Specification](https://docs.starkware.co/starkex/crypto/stark-curve.html)
- [StarkEx Documentation](https://docs.starkware.co/starkex/)
