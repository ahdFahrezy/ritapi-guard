# RITAPI Advance - WAF System

## Overview
RITAPI Advance is a Web Application Firewall (WAF) system that provides security checks and intelligent routing to multiple backend services.

## Key Features

### Dynamic Service Routing
The system now supports dynamic routing to multiple backend services using the `x-target-id` header:

- **Header Required**: `x-target-id` must be included in all requests
- **Value Format**: UUID that corresponds to a registered service
- **Dynamic Backend**: Each request is routed to the appropriate backend based on the service UUID

### Security Checks
The WAF performs comprehensive security analysis:

1. **TLS Analysis**: Certificate validation and security assessment
2. **ASN Scoring**: Autonomous System Number reputation scoring
3. **IP Reputation**: IP address threat assessment
4. **JSON Validation**: Schema validation for JSON payloads
5. **Behavioral Analysis**: Anomaly detection using machine learning
6. **Blocklist Management**: IP blocking and alerting system

## Usage

### Client Request Format
```bash
curl -X POST "https://your-waf-domain.com/api/endpoint" \
  -H "x-target-id: 550e8400-e29b-41d4-a716-446655440000" \
  -H "Content-Type: application/json" \
  -d '{"key": "value"}'
```

### Required Headers
- `x-target-id`: UUID of the target service (required)

### Response Headers
- `X-Target-Service`: UUID of the service that processed the request
- `X-Target-URL`: Base URL of the target backend
- `X-Cache-Status`: Cache status (hit, stored, disabled, etc.)

## Service Management

### Adding a New Service
1. Access Django admin at `/admin/`
2. Navigate to "Ops services" → "Services"
3. Click "Add Service"
4. Enter the target backend URL
5. Save to generate a new UUID

### Service Configuration
- **UUID**: Automatically generated unique identifier
- **Target Base URL**: Full URL of the backend service (e.g., `https://api.example.com`)
- **Timestamp**: Automatic creation timestamp

## Error Responses

### Missing Header
```json
{
  "error": "Missing required header",
  "detail": "x-target-id header is required"
}
```
**Status**: 400

### Invalid UUID Format
```json
{
  "error": "Invalid target ID format",
  "detail": "x-target-id must be a valid UUID"
}
```
**Status**: 400

### Service Not Found
```json
{
  "error": "Target service not found",
  "detail": "No service found with ID: 550e8400-e29b-41d4-a716-446655440000"
}
```
**Status**: 404

### Security Block
```json
{
  "error": "Blocked by RITAPI",
  "score": -5.0
}
```
**Status**: 403

## Configuration

### Environment Variables
- `ENABLE_BACKEND_CACHE`: Enable/disable Redis caching (default: True)
- `REDIS_URL`: Redis connection URL (default: redis://127.0.0.1:6379/0)
- `BACKEND_RESPONSE_CACHE_TTL`: Cache TTL in seconds (default: 30)
- `ALLOW_IPS`: List of IPs to bypass security checks

### Cache Configuration
- **GET/HEAD requests**: Cached for configurable TTL
- **Cache Key**: Includes method, path, headers, target ID, and body hash
- **Cache Headers**: Automatically added to responses

## Security Features

### IP Whitelisting
Configure `ALLOW_IPS` in settings to bypass security checks for trusted IPs.

### Automatic Blocking
- **Score-based**: IPs with security score < -4 are automatically blocked
- **JSON validation**: Malformed JSON requests are blocked
- **Blocklist**: Previously blocked IPs are denied access

### Alerting
- Security events trigger automatic alerts
- Blocked requests create high-severity alerts
- Backend errors create critical alerts

## Monitoring

### Request Logging
All requests are logged to the database with:
- Client IP address
- Request path and method
- Security score and decision
- Blocking reason (if applicable)

### Performance Metrics
- Response time tracking
- Cache hit rates
- Security score distribution
- Blocking statistics

## Development

### Running Locally
```bash
# Activate virtual environment
source venv/Scripts/activate  # Windows
source venv/bin/activate      # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Create superuser for admin access
python manage.py createsuperuser

# Run development server
python manage.py runserver
```

### Testing
```bash
# Run tests
python manage.py test

# Run specific app tests
python manage.py test decision_engine
python manage.py test ops.ops_services
```

## Architecture

### Components
- **Decision Engine**: Core WAF logic and security checks
- **Service Router**: Dynamic backend routing based on UUID
- **Security Modules**: TLS, ASN, IP reputation, JSON validation
- **Cache Layer**: Redis-based response caching
- **Admin Interface**: Service management and monitoring

### Data Flow
1. Client request with `x-target-id` header
2. Service lookup and validation
3. Security checks (TLS, ASN, IP reputation, JSON, behavior)
4. Score calculation and decision making
5. Request forwarding to target backend
6. Response caching and logging
7. Response delivery to client

## Troubleshooting

### Common Issues
- **Service not found**: Verify UUID exists in admin panel
- **Redis connection**: Check Redis server status and URL
- **Import errors**: Ensure all required apps are in INSTALLED_APPS
- **Permission denied**: Check database permissions and migrations

### Logs
- **Application logs**: Check Django logs for errors
- **Security logs**: Review RequestLog model entries
- **Cache logs**: Monitor Redis operations
- **Alert logs**: Check alert and blocking service logs
