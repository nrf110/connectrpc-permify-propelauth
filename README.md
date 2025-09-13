# ConnectRPC Permify PropelAuth Integration

A Go library that provides PropelAuth authentication for ConnectRPC services with Permify authorization integration.

## Installation

```bash
go get github.com/nrf110/connectrpc-permify-propelauth
```

## Setup

### Basic Configuration

Create a PropelAuth authenticator for use with the ConnectRPC Permify interceptor:

```go
package main

import (
    "log"

    connectpermify "github.com/nrf110/connectrpc-permify/pkg"
    propelauth "github.com/nrf110/connectrpc-permify-propelauth/pkg"
    propelclient "github.com/propelauth/propelauth-go/pkg"
)

func main() {
    // Initialize PropelAuth client
    client, err := propelclient.InitBaseAuth("https://your-auth-url.propelauth.com", "your-api-key", nil)
    if err != nil {
        log.Fatal("Failed to initialize PropelAuth client:", err)
    }

    // Create ID extractor for API keys without associated users
    idExtractor := propelauth.DefaultIDExtractor("service_id")

    // Create the authenticator
    authenticator := propelauth.NewPropelAuthenticator(client, idExtractor)

    // Use with ConnectRPC Permify interceptor
    interceptor := connectpermify.NewAuthorizationInterceptor(authenticator, permifyClient)

    // Apply to your ConnectRPC server
    // server := connect.NewServer(handler, connect.WithInterceptors(interceptor))
}
```

### Authentication Methods

The authenticator supports two authentication methods:

1. **OAuth Token** - Pass in `Authorization` header
2. **API Key** - Pass in `X-Api-Key` header

### Accessing Principal Information

Retrieve the authenticated principal in your handlers:

```go
func (s *MyService) MyHandler(ctx context.Context, req *connect.Request[MyRequest]) (*connect.Response[MyResponse], error) {
    principal := propelauth.GetPrincipal(ctx)

    // Access user information
    if principal.User != nil {
        userID := principal.User.ID
        email := principal.User.Email
        // ... use user data
    }

    // Access organization information
    if principal.ActiveOrg != nil {
        orgID := principal.ActiveOrg.ID
        orgName := principal.ActiveOrg.Name
        // ... use org data
    }

    return connect.NewResponse(&MyResponse{}), nil
}
```

## Development

### Using the Dev Container

This project includes a dev container configuration for consistent development environments.

#### Prerequisites

- Docker
- VS Code with Dev Containers extension, or
- JetBrains IDE with Docker support

#### Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/nrf110/connectrpc-permify-propelauth.git
   cd connectrpc-permify-propelauth
   ```

2. Open in VS Code and select "Reopen in Container" when prompted, or use the command palette: `Dev Containers: Reopen in Container`

3. The dev container includes:
   - Go 1.24
   - Buf for Protocol Buffer management
   - grpcurl for API testing
   - All necessary Go tools and extensions

#### Running Tests

```bash
make test
```

#### Development Tools

The dev container comes pre-configured with:

- `buf` - Protocol buffer toolchain
- `grpcurl` - Command-line gRPC client
- `protoc-gen-go` - Go protocol buffer compiler
- `protoc-gen-connect-go` - ConnectRPC code generator

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes using the dev container
4. Run tests: `make test`
5. Submit a pull request

## API Reference

### Types

- `PropelAuthenticator` - Main authenticator implementation
- `PropelAuthPrincipal` - Contains authenticated user and organization data
- `IDExtractor` - Function type for extracting IDs from API key metadata

### Functions

- `NewPropelAuthenticator(client propelauth.ClientInterface, idExtractor IDExtractor)` - Creates new authenticator
- `GetPrincipal(ctx context.Context)` - Retrieves principal from request context
- `DefaultIDExtractor(metadataKey string)` - Creates default ID extractor for API keys

## License

MIT License

Copyright (c) 2025 Nick Fisher

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
