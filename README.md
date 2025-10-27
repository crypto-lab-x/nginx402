# nginx x402 Payment Module

An nginx module implementing the X402 Payment Required HTTP status code for blockchain payments. This module allows web servers to require payment for access to resources, supporting multiple blockchain networks.

## Overview

The X402 Payment Required protocol enables websites to request cryptocurrency payments before granting access to content. This nginx module provides:

- **Payment verification** using cryptographic signatures
- **Multi-network support** for Ethereum, Solana, Base, and other EVM-compatible chains
- **Configurable payment requirements** per location
- **ECDSA signature verification** for payment authenticity
- **Flexible integration** with external payment verification services

## Features

- ✅ Block/allow based on payment verification
- ✅ Support for multiple blockchain networks
- ✅ ECDSA signature verification (secp256k1)
- ✅ Configurable payment amounts and currencies
- ✅ Payment requirements specification (X402 protocol)
- ✅ JSON-based payment required responses
- ✅ Integration with external payment verification APIs
- ✅ Headers injection for backend services

## Requirements

### System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install build-essential nginx-dev libssl-dev libcurl4-openssl-dev
```

**CentOS/RHEL:**
```bash
sudo yum install gcc gcc-c++ nginx-devel openssl-devel libcurl-devel
```

**macOS:**
```bash
brew install nginx openssl curl
```

### Software Versions

- nginx >= 1.18.0
- OpenSSL >= 1.1.1
- libcurl >= 7.50.0
- GCC >= 7.0

## Building

### Prerequisites

1. Clone this repository:
   ```bash
   git clone <repository-url>
   cd nginx402
   ```

2. Set the nginx source directory (if nginx isn't installed or you want to use a specific version):
   ```bash
   export NGINX_SRC=/path/to/nginx-source
   ```

   Or download nginx source:
   ```bash
   wget http://nginx.org/download/nginx-1.18.0.tar.gz
   tar -xzf nginx-1.18.0.tar.gz
   export NGINX_SRC=$(pwd)/nginx-1.18.0
   ```

### Build

Run the build script:
```bash
chmod +x build.sh
./build.sh
```

The compiled module will be available at `modules/ngx_http_x402_module.so`.

## Installation

1. Copy the module to nginx modules directory:
   ```bash
   sudo cp modules/ngx_http_x402_module.so /etc/nginx/modules/
   ```

2. Load the module in nginx configuration. Add at the top of `/etc/nginx/nginx.conf`:
   ```nginx
   load_module modules/ngx_http_x402_module.so;
   ```

3. Test configuration:
   ```bash
   sudo nginx -t
   ```

4. Reload nginx:
   ```bash
   sudo nginx -s reload
   ```

## Configuration

### Basic Configuration

Add the module configuration to your nginx server or location block:

```nginx
server {
    listen 80;
    server_name example.com;

    location /premium {
        x402_enabled on;
        x402_algorithm "secp256k1";
        x402_timeout 30s;
        
        # Define payment requirements
        x402_payment {
            scheme "exact";
            network "ethereum";
            max_amount_required "1000000000000000000";  # 1 ETH in wei
            pay_to "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb";
            max_timeout_seconds 300;
            asset "native";
            description "Premium content access";
            mime_type "text/html";
        }
    }
}
```

### Network Examples

#### Ethereum Mainnet

```nginx
x402_payment {
    scheme "exact";
    network "ethereum";
    max_amount_required "1000000000000000000";  # 1 ETH (18 decimals)
    pay_to "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb";
    max_timeout_seconds 300;
    asset "native";
    description "Ethereum payment required";
    mime_type "application/json";
}
```

#### Solana

```nginx
x402_payment {
    scheme "exact";
    network "solana";
    max_amount_required "1000000000";  # 1 SOL (9 decimals)
    pay_to "11111111111111111111111111111111";  # Solana wallet address
    max_timeout_seconds 300;
    asset "native";
    description "Solana payment required";
    mime_type "application/json";
}
```

#### Base (L2 Network)

```nginx
x402_payment {
    scheme "exact";
    network "base";
    max_amount_required "1000000000000000000";  # 1 ETH equivalent
    pay_to "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb";
    max_timeout_seconds 300;
    asset "native";
    description "Base network payment required";
    mime_type "application/json";
}
```

### External Payment Verification

To use an external service for payment verification:

```nginx
location /api {
    x402_enabled on;
    x402_payment_endpoint "https://payment-verifier.example.com";
}
```

### Configuration Directives

| Directive | Context | Default | Description |
|-----------|---------|---------|-------------|
| `x402_enabled` | main, server, location | off | Enable/disable the module |
| `x402_public_key` | main, server, location | - | Public key for signature verification |
| `x402_private_key` | main, server, location | - | Private key for signature creation |
| `x402_algorithm` | main, server, location | secp256k1 | Signature algorithm |
| `x402_timeout` | main, server, location | 30s | Payment timeout |
| `x402_payment_endpoint` | main, server, location | - | External payment verification endpoint |
| `x402_version` | main, server, location | 1 | X402 protocol version |
| `x402_payment` | location | - | Payment requirements block |

### Payment Block Directives

Within `x402_payment` block:

| Directive | Type | Required | Description |
|-----------|------|----------|-------------|
| `scheme` | string | Yes | Payment scheme (e.g., "exact") |
| `network` | string | Yes | Blockchain network ID |
| `max_amount_required` | string | Yes | Maximum payment amount in atomic units |
| `pay_to` | string | Yes | Recipient address |
| `max_timeout_seconds` | number | Yes | Payment timeout in seconds |
| `asset` | string | No | ERC20 contract address or "native" |
| `description` | string | No | Payment description |
| `mime_type` | string | No | Resource MIME type |
| `extra` | string | No | Additional JSON data |

## API Usage

### Request Format

Clients send payment verification using the `X-PAYMENT` header in base64-encoded JSON format:

```bash
X-PAYMENT: eyJ4NDAyVmVyc2lvbiI6Miwic2NoZW1lIjoiZXhhY3QiLCJuZXR3b3JrIjoiZXRoZXJldW0iLCJwYXlsb2FkIjoiLi4uIn0=
```

The decoded JSON structure:
```json
{
  "x402Version": 2,
  "scheme": "exact",
  "network": "ethereum",
  "payload": "..."
}
```

### Payment Required Response

When payment is required, the server responds with HTTP 402 and a JSON body:

```json
{
  "x402Version": 2,
  "accepts": [
    {
      "scheme": "exact",
      "network": "ethereum",
      "maxAmountRequired": "1000000000000000000",
      "resource": "/api/premium",
      "description": "Premium content access",
      "mimeType": "text/html",
      "payTo": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
      "maxTimeoutSeconds": 300,
      "asset": "native"
    }
  ]
}
```

### Verified Request Headers

After successful verification, the following headers are added to the request:

- `X-X402-Verified: true` - Verification status
- `X-X402-Network: ethereum` - Blockchain network
- `X-X402-Amount: 1000000000000000000` - Payment amount
- `X-X402-Transaction-Id: 0x...` - Transaction ID

## Security Considerations

- **Private keys** should be stored securely and never exposed in configuration files
- **Public keys** must match the private key used for signing
- **Timeouts** should be set appropriately to prevent replay attacks
- **HTTPS** is strongly recommended for production deployments
- **Signature verification** ensures payment authenticity
- **Network validation** limits accepted blockchain networks

## Development

### Project Structure

```
nginx402/
├── src/
│   ├── ngx_http_x402_module.c    # Main module implementation
│   ├── ngx_http_x402_module.h     # Module header definitions
│   └── ngx_http_x402_utils.c     # Utility functions
├── config/
│   └── nginx.example               # Example nginx configuration
├── modules/                        # Compiled module (after build)
├── build.sh                        # Build script
├── requirements.txt                # Dependency versions
└── README.md                       # This file
```

### Testing

1. Start nginx with the module loaded
2. Make requests with valid/invalid payment headers
3. Verify HTTP 402 responses when payment is required
4. Verify access when payment is valid

## Troubleshooting

### Module fails to load

Check nginx error logs:
```bash
sudo tail -f /var/log/nginx/error.log
```

Ensure the module was compiled against the same nginx version:
```bash
nginx -V
```

### Payment verification fails

Enable debug logging:
```nginx
error_log /var/log/nginx/error.log debug;
```

### Compilation errors

Ensure all dependencies are installed:
```bash
pkg-config --exists openssl && echo "OpenSSL OK" || echo "OpenSSL missing"
pkg-config --exists libcurl && echo "curl OK" || echo "curl missing"
```

## License

MIT License

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## References

- [HTTP 402 Payment Required](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/402)
- [X402 Protocol Specification](https://www.coinbase.com/ru/developer-platform/products/x402)
