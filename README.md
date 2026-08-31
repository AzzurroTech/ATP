# atp (AzzurroTech Platform)

**MIT License © Azzurro Technology Inc.**

## Overview

The ATP (AzzurroTech Platform) serves as the central integration hub for all AzzurroTech services. It provides service discovery, configuration management, authentication, and API gateway functionality that connects all AzzurroTech and Emperor42 projects.

## Installation

### Prerequisites
- Go 1.20+
- SQLite database

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/azzurro-tech/atp.git
   cd atp
   ```

2. Install Go dependencies:
   ```bash
   go mod download
   ```

3. Start the ATP platform:
   ```bash
   cd azzurrotech/atp
   ./atp
   # or
   go run .
   ```

4. Access the ATP web interface:
   ```
   http://localhost:8080
   http://localhost:8080/atp/config
   http://localhost:8080/atp/admin
   ```

## Usage (Standalone)

### Basic Operations

**Service Management**
```bash
# Register a new service
curl -X POST http://localhost:8080/api/services/register \
  -H "Content-Type: application/json" \
  -d '{"name":"my-service","endpoint":"http://localhost:8081","health":"/health"}'

# List all services
curl http://localhost:8080/api/services

# Get service details
curl http://localhost:8080/api/services/{service-name}
```

**Configuration Management**
```bash
# Get current configuration
curl http://localhost:8080/api/config

# Update configuration
curl -X PUT http://localhost:8080/api/config \
  -H "Content-Type: application/json" \
  -d '{"auto_register":true,"health_check_interval":30}'
```

**Client Management**
```bash
# List clients
curl http://localhost:8080/clients

# Create new client
curl -X POST http://localhost:8080/clients \
  -H "Content-Type: application/json" \
  -d '{"name":"Client Name","email":"client@example.com","plan":"enterprise"}'
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main ATP status page |
| `/atp` | GET | HTML config viewer |
| `/atp/config` | GET | View configuration |
| `/atp/config` | POST | Update configuration |
| `/atp/admin` | GET | HTML admin panel |
| `/atp/admin` | POST | Update admin settings |
| `/api/services` | GET | List all services |
| `/api/services/{name}` | GET | Get service details |
| `/api/services/register` | POST | Register new service |
| `/api/config` | GET | Get configuration |
| `/api/config` | PUT | Update configuration |
| `/api/clients` | GET | List clients (admin) |
| `/api/billing` | GET | Billing information (admin) |
| `/health` | GET | Health check |

## Integration with ATP

### Service Registration

All AzzurroTech and Emperor42 services register with ATP using the service registry:

```go
// Example service registration
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    
    // Health check endpoint
    r.GET("/health", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "healthy"})
    })
    
    // Service registration with ATP
    r.POST("/register", func(c *gin.Context) {
        var config map[string]interface{}
        if err := c.BindJSON(&config); err != nil {
            c.JSON(400, gin.H{"error": "invalid config"})
            return
        }
        
        // Register with ATP
        response, err := registerWithATP(config)
        if err != nil {
            c.JSON(500, gin.H{"error": "registration failed"})
            return
        }
        
        c.JSON(200, response)
    })
    
    r.Run(":8080")
}
```

### Configuration Distribution

ATP distributes configuration to all registered services:

```yaml
# atp/config/integrations.yaml
integrations:
  azzurrotech:
    pod:
      health_check: /health
      forms_endpoint: /api/forms
      data_endpoint: /api/data
      config_endpoint: /api/pod/config
      admin_endpoint: /api/pod/admin
    song:
      health_check: /health
      auth_endpoint: /api/auth
      token_endpoint: /api/tokens
      config_endpoint: /api/song/config
    shepherd:
      health_check: /health
      billing_endpoint: /api/billing
      auth_endpoint: /api/auth
      config_endpoint: /api/shepherd/config
  emperor42:
    VENI:
      template_endpoint: /api/components
    VIDI:
      data_endpoint: /api/data
    VICI:
      changes_endpoint: /api/changes
    VINI:
      workflow_endpoint: /api/workflows
```

### Service Discovery

Services discover each other through ATP:

```bash
# Service discovery through ATP
curl http://localhost:8080/api/services

# Get specific service details
curl http://localhost:8080/api/services/pod

# Health check for a service
curl http://localhost:8080/api/services/pod/health
```

## Development Setup

### Local Development

```bash
# Start ATP platform
cd azzurrotech/atp
./atp

# Or with Go run
cd azzurrotech/atp
go run .

# Test ATP functionality
curl http://localhost:8080/health
curl http://localhost:8080/api/services
curl http://localhost:8080/api/config
```

### Testing

```bash
# Run all tests
cd azzurrotech/atp
go test ./...

# Run specific test package
cd azzurrotech/atp
go test ./internal/service_registry_test.go

# Test API endpoints
curl -X POST http://localhost:8080/api/services/register \
  -H "Content-Type: application/json" \
  -d '{"name":"test-service","endpoint":"http://localhost:8081","health":"/health"}'
```

### Building

```bash
# Build for production
cd azzurrotech/atp
go build -o atp ./...

# Build with specific options
cd azzurrotech/atp
go build -ldflags="-port=8080" -o atp ./...

# Build with specific configuration
cd azzurrotech/atp
PORT=8080 CONFIG_FILE=config.yaml go run .
```

## Performance Optimization

### Health Monitoring

- **HTTP Health Checks**: Regular health checks for all services
- **Metrics Collection**: Performance metrics and statistics
- **Error Tracking**: Real-time error monitoring
- **Log Aggregation**: Centralized logging for troubleshooting

### Configuration Caching

ATP caches configuration to reduce database load:

```go
// Configuration caching example
var configCache = make(map[string]interface{})

func getCachedConfig(key string) (interface{}, bool) {
    if config, exists := configCache[key]; exists {
        return config, true
    }
    return nil, false
}

func setCachedConfig(key string, value interface{}) {
    configCache[key] = value
}
```

## Monitoring

### Health Endpoints

```bash
# ATP health check
curl http://localhost:8080/health

# Service health
curl http://localhost:8080/api/services/pod/health

# Configuration health
curl http://localhost:8080/api/config

# Billing system health
curl http://localhost:8080/api/billing
```

### Metrics

ATP collects and reports:

- **Service Status**: All registered services status
- **Configuration Health**: Configuration distribution status
- **Client Status**: Active client count
- **API Performance**: HTTP request/response metrics
- **Error Rates**: API error tracking

## Security Features

### ATP Security

- **Service Authentication**: Secure service registration and authentication
- **Configuration Encryption**: Encrypted configuration storage
- **Access Control**: Role-based access control for admin functions
- **Audit Trails**: Complete logging of all administrative actions
- **Rate Limiting**: API rate limiting to prevent abuse
- **Input Validation**: Validates all input to prevent injection attacks

### Integration Security

ATP provides secure integration between services:

- **Service Discovery**: Secure service registration and discovery
- **Configuration Distribution**: Encrypted configuration distribution
- **Health Monitoring**: Secure health monitoring
- **API Gateway**: Centralized API security and logging

## Troubleshooting

### Common Issues

1. **Service Registration Failed**
   ```bash
   # Check ATP logs
   $ tail -f atp.log
   
   # Test ATP health
   $ curl http://localhost:8080/health
   ```

2. **Configuration Not Loaded**
   ```bash
   # Check configuration
   $ curl http://localhost:8080/api/config
   
   # Restart ATP
   $ pkill atp
   $ cd azzurrotech/atp && ./atp
   ```

3. **Service Not Discovered**
   ```bash
   # Check service registration
   $ curl http://localhost:8080/api/services
   
   # Verify service health
   $ curl http://localhost:8080/api/services/{service-name}/health
   ```

### Debugging Commands

```bash
# Enable debug logging
export ATP_LOG_LEVEL=debug

# Check service logs
$ tail -f atp.log

# Monitor system resources
$ top
$ free -h

# Test service discovery
$ curl http://localhost:8080/api/services

# Test API endpoints
$ curl http://localhost:8080/api/config
$ curl http://localhost:8080/api/clients
```

## API Specifications

### High Maturity API (JSON-based)

```http
GET /api/services
GET /api/services/{name}
POST /api/services/register
GET /api/config
PUT /api/config
GET /api/clients
GET /api/billing
GET /health
```

### ATP-specific Endpoints

```http
GET /atp/config - HTML config viewer
POST /atp/config - HTML config updater
GET /atp/admin - HTML admin panel
POST /atp/admin - HTML admin updater
```

## Future Enhancements

### Planned Features

1. **Advanced Monitoring**: Real-time dashboard with performance metrics
2. **Automated Scaling**: Auto-scaling based on service load
3. **Multi-tenancy**: Support for multiple organizations and clients
4. **Advanced Security**: AI-powered threat detection
5. **Configuration Templates**: Predefined configuration templates

### Roadmap

- **Phase 1**: Core service discovery and registration
- **Phase 2**: Advanced configuration management
- **Phase 3**: Enhanced security and monitoring
- **Phase 4**: Multi-tenancy and enterprise features

## Conclusion

The ATP platform is the foundation of the AzzurroTech ecosystem. It provides essential service discovery, configuration management, and security features that enable all AzzurroTech and Emperor42 projects to work together seamlessly.

Key benefits:

- **Unified Integration**: Single point of integration for all services
- **Centralized Management**: Centralized configuration and monitoring
- **Enhanced Security**: Secure service discovery and communication
- **Scalable Architecture**: Supports growth and future enhancements
- **Production Ready**: Comprehensive error handling and monitoring

The ATP platform is production-ready and can be easily integrated into enterprise applications with robust service discovery and management capabilities.

---

*Document Version: 1.0*
*Created: 2026-08-25*
*Last Updated: 2026-08-25*
*Status: Production Ready*

**License:** MIT License © Azzurro Technology Inc.