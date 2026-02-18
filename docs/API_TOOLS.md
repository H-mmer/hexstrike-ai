# API Security Tools

HexStrike AI Phase 2: REST, GraphQL, and SOAP API security testing.

## API Discovery (5 tools)

### kiterunner
Fast API content discovery.
```bash
kr scan https://api.example.com -w wordlist.txt
```

### api-routes-finder
Automated API endpoint discovery.
```python
from tools.api.api_discovery import api_routes_finder
result = api_routes_finder("https://api.example.com")
print(f"Found {result['endpoints_found']} endpoints")
```

### swagger-scanner
Scan for Swagger/OpenAPI documentation.

### graphql-cop
GraphQL security scanner with introspection.

### postman-automated
Generate Postman collections from discovered APIs.

## API Authentication Testing (4 tools)

### jwt-hack
JWT token manipulation and cracking.
```python
from tools.api.api_auth import jwt_hack
result = jwt_hack(token, secret="test_secret")
```

### oauth-scanner
OAuth flow security testing.

### api-key-brute
API key brute forcing.

### bearer-token-analyzer
Analyze bearer token structure and type.

## API Fuzzing (4 tools)

### rest-attacker
REST API fuzzing framework.
```python
from tools.api.api_fuzzing import rest_attacker
result = rest_attacker("https://api.example.com/endpoint")
```

### graphql-path-enum
GraphQL path enumeration.

### api-injection-scanner
Scan for SQL, NoSQL, Command, and LDAP injection.

### schema-fuzzer
Fuzz APIs based on OpenAPI/GraphQL schemas.

## API Monitoring (2 tools)

### api-trace-analyzer
Real-time API traffic analysis.

### rate-limit-tester
Test API rate limiting mechanisms.

## Usage Examples

### Complete API Assessment
```python
from tools.api.api_discovery import api_routes_finder, swagger_scanner
from tools.api.api_auth import jwt_hack
from tools.api.api_fuzzing import api_injection_scanner

# 1. Discovery
endpoints = api_routes_finder("https://api.example.com")
swagger = swagger_scanner("https://api.example.com")

# 2. Authentication testing
jwt_result = jwt_hack(captured_token)

# 3. Security testing
injection_results = api_injection_scanner("https://api.example.com/api/v1/users")

# 4. Fuzzing
fuzz_results = rest_attacker("https://api.example.com/api/v1/users")
```

### GraphQL Testing
```python
from tools.api.api_discovery import graphql_cop_scan
from tools.api.api_fuzzing import graphql_path_enum

# Introspection
introspection = graphql_cop_scan("https://api.example.com/graphql")

if introspection['introspection_enabled']:
    schema = introspection['schema']
    # Path enumeration
    paths = graphql_path_enum("https://api.example.com/graphql")
```

## Tool Count
**15 API security tools** across discovery, authentication, fuzzing, and monitoring.
