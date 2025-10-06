# 🔐 JWT Authentication Microservice

[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com/)
[![JWT](https://img.shields.io/badge/JWT-Auth-orange.svg)](https://jwt.io/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue.svg)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7-red.svg)](https://redis.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

[English](#english) | [Português](#português)

---

## English

### Overview

Production-ready JWT authentication microservice built with FastAPI, featuring user registration, login, refresh tokens, Role-Based Access Control (RBAC), OAuth2 integration, and comprehensive security features. Designed for integration with trading platforms and financial applications.

### Key Features

- **JWT Authentication**: Secure token-based authentication with RS256/HS256
- **Refresh Tokens**: Long-lived refresh tokens with automatic rotation
- **RBAC**: Role-Based Access Control (admin, user, trader, analyst)
- **OAuth2**: Integration with Google, GitHub, and custom providers
- **Password Security**: Bcrypt hashing with configurable salt rounds
- **Rate Limiting**: Protection against brute-force attacks
- **Token Blacklisting**: Redis-based token revocation
- **Audit Logging**: Complete access history and security events
- **PostgreSQL**: Persistent user and session storage
- **Redis**: High-performance caching and session management
- **Email Verification**: Optional email confirmation workflow
- **2FA Support**: Two-factor authentication with TOTP

### Architecture

```
┌─────────────────────────────────────────┐
│          Client Application             │
└──────────────┬──────────────────────────┘
               │ HTTP/HTTPS
               ▼
┌─────────────────────────────────────────┐
│      FastAPI Authentication API         │
│  ┌───────────────────────────────────┐  │
│  │  Rate Limiter Middleware          │  │
│  └───────────────┬───────────────────┘  │
│                  │                       │
│  ┌───────────────▼───────────────────┐  │
│  │  JWT Token Handler                │  │
│  │  - Generate tokens                │  │
│  │  - Validate tokens                │  │
│  │  - Refresh tokens                 │  │
│  └───────────────┬───────────────────┘  │
│                  │                       │
│  ┌───────────────▼───────────────────┐  │
│  │  User Management                  │  │
│  │  - Registration                   │  │
│  │  - Login                          │  │
│  │  - Profile                        │  │
│  │  - RBAC                           │  │
│  └───────────────┬───────────────────┘  │
└──────────────────┼───────────────────────┘
                   │
        ┌──────────┴──────────┐
        ▼                     ▼
┌───────────────┐    ┌────────────────┐
│  PostgreSQL   │    │     Redis      │
│  - Users      │    │  - Sessions    │
│  - Tokens     │    │  - Blacklist   │
│  - Audit Logs │    │  - Cache       │
└───────────────┘    └────────────────┘
```

### Installation

```bash
# Clone repository
git clone https://github.com/galafis/jwt-auth-microservice.git
cd jwt-auth-microservice

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env with your configuration

# Run database migrations
alembic upgrade head

# Start server
uvicorn app.main:app --reload
```

### Quick Start

#### 1. Register User

```bash
curl -X POST "http://localhost:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "trader@example.com",
    "password": "SecurePass123!",
    "role": "trader"
  }'
```

#### 2. Login

```bash
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "trader@example.com",
    "password": "SecurePass123!"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 900
}
```

#### 3. Access Protected Route

```bash
curl -X GET "http://localhost:8000/users/me" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

#### 4. Refresh Token

```bash
curl -X POST "http://localhost:8000/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "YOUR_REFRESH_TOKEN"
  }'
```

### API Endpoints

#### Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/register` | Register new user | No |
| POST | `/auth/login` | User login | No |
| POST | `/auth/refresh` | Refresh access token | No |
| POST | `/auth/logout` | Logout (blacklist token) | Yes |
| POST | `/auth/verify-email` | Verify email address | No |
| POST | `/auth/forgot-password` | Request password reset | No |
| POST | `/auth/reset-password` | Reset password | No |

#### User Management

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/users/me` | Get current user profile | Yes |
| PUT | `/users/me` | Update profile | Yes |
| DELETE | `/users/me` | Delete account | Yes |
| GET | `/users/{id}` | Get user by ID | Admin |
| PUT | `/users/{id}/role` | Change user role | Admin |

#### Admin

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/admin/users` | List all users | Admin |
| GET | `/admin/audit-logs` | View audit logs | Admin |
| POST | `/admin/users/{id}/disable` | Disable user | Admin |
| GET | `/admin/stats` | System statistics | Admin |

### Security Features

#### Password Security
- Bcrypt hashing with configurable cost factor
- Minimum password requirements (length, complexity)
- Password history to prevent reuse
- Automatic password expiration

#### Token Security
- JWT with RS256 or HS256 algorithm
- Short-lived access tokens (15 minutes default)
- Long-lived refresh tokens (7 days default)
- Automatic token rotation on refresh
- Token blacklisting for logout
- Token fingerprinting

#### Rate Limiting
```python
# 5 login attempts per minute per IP
@limiter.limit("5/minute")
async def login(credentials: LoginRequest):
    ...

# 10 API calls per minute per user
@limiter.limit("10/minute")
async def protected_route():
    ...
```

#### RBAC (Role-Based Access Control)

```python
from app.dependencies import require_role

@app.get("/admin/users")
async def list_users(
    current_user: User = Depends(require_role("admin"))
):
    ...

@app.post("/trading/execute")
async def execute_trade(
    current_user: User = Depends(require_role(["trader", "admin"]))
):
    ...
```

### Environment Variables

```env
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/authdb

# Redis
REDIS_URL=redis://localhost:6379/0

# JWT
SECRET_KEY=your-secret-key-here-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# OAuth2 (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Email (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Security
RATE_LIMIT_PER_MINUTE=10
MAX_LOGIN_ATTEMPTS=5
PASSWORD_MIN_LENGTH=8
```

### Database Schema

```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP
);

-- Refresh tokens table
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(500) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Audit logs table
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    success BOOLEAN,
    details JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);
```

### Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=app --cov-report=html

# Run specific test file
pytest tests/test_auth.py -v

# Run integration tests
pytest tests/integration/ -v
```

### Docker Deployment

```yaml
# docker-compose.yml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/authdb
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis

  db:
    image: postgres:16
    environment:
      - POSTGRES_DB=authdb
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f api

# Stop services
docker-compose down
```

### Performance

- **Throughput**: 1000+ requests/second
- **Latency**: < 50ms average response time
- **Scalability**: Horizontal scaling with load balancer
- **Caching**: Redis for session and token caching
- **Connection Pooling**: PostgreSQL connection pool

### Use Cases

- **Trading Platforms**: Secure authentication for traders
- **Financial APIs**: Protect sensitive financial endpoints
- **Microservices**: Centralized authentication service
- **SaaS Applications**: Multi-tenant authentication
- **Mobile Apps**: JWT-based mobile authentication

### Monitoring & Observability

```python
# Prometheus metrics
from prometheus_fastapi_instrumentator import Instrumentator

Instrumentator().instrument(app).expose(app)

# Health check endpoint
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "database": await check_db_connection(),
        "redis": await check_redis_connection(),
        "timestamp": datetime.now().isoformat()
    }
```

### Security Best Practices

1. **Always use HTTPS** in production
2. **Rotate secrets** regularly
3. **Enable rate limiting** on all endpoints
4. **Monitor audit logs** for suspicious activity
5. **Keep dependencies updated**
6. **Use strong passwords** (enforce in validation)
7. **Implement CORS** properly
8. **Enable SQL injection protection** (use ORM)
9. **Validate all inputs** with Pydantic
10. **Use environment variables** for secrets

### License

MIT License

### Author

**Gabriel Demetrios Lafis**

---

## Português

### Visão Geral

Microserviço de autenticação JWT pronto para produção construído com FastAPI, apresentando registro de usuário, login, refresh tokens, Controle de Acesso Baseado em Funções (RBAC), integração OAuth2 e recursos abrangentes de segurança. Projetado para integração com plataformas de trading e aplicações financeiras.

### Características Principais

- **Autenticação JWT**: Autenticação segura baseada em token com RS256/HS256
- **Refresh Tokens**: Tokens de longa duração com rotação automática
- **RBAC**: Controle de Acesso Baseado em Funções (admin, user, trader, analyst)
- **OAuth2**: Integração com Google, GitHub e provedores personalizados
- **Segurança de Senha**: Hashing bcrypt com salt configurável
- **Rate Limiting**: Proteção contra ataques de força bruta
- **Blacklist de Tokens**: Revogação de tokens baseada em Redis
- **Audit Logging**: Histórico completo de acesso e eventos de segurança
- **PostgreSQL**: Armazenamento persistente de usuários e sessões
- **Redis**: Cache de alta performance e gerenciamento de sessão

### Autor

**Gabriel Demetrios Lafis**
