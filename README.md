# 🔐 JWT Authentication Microservice

[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com/)
[![JWT](https://img.shields.io/badge/JWT-Auth-orange.svg)](https://jwt.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Production-ready JWT authentication microservice with FastAPI, featuring user registration, login, refresh tokens, RBAC, and OAuth2 integration.

## Features

- **JWT Authentication**: Secure token-based authentication
- **Refresh Tokens**: Long-lived refresh tokens with rotation
- **RBAC**: Role-Based Access Control (admin, user, trader)
- **OAuth2**: Integration with Google and GitHub
- **Password Security**: Bcrypt hashing with salt
- **Rate Limiting**: Protection against brute-force attacks
- **Audit Logging**: Complete access history
- **PostgreSQL**: Persistent user storage
- **Redis**: Token blacklisting and session management

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run server
uvicorn app.main:app --reload

# Access docs
http://localhost:8000/docs
```

## API Endpoints

### Authentication
- `POST /auth/register` - User registration
- `POST /auth/login` - User login (returns access + refresh tokens)
- `POST /auth/refresh` - Refresh access token
- `POST /auth/logout` - Logout (blacklist token)

### User Management
- `GET /users/me` - Get current user profile
- `PUT /users/me` - Update profile
- `DELETE /users/me` - Delete account

### Admin
- `GET /admin/users` - List all users (admin only)
- `PUT /admin/users/{id}/role` - Change user role (admin only)

## Security Features

- Password hashing with bcrypt
- JWT with RS256 algorithm
- Token expiration (15min access, 7 days refresh)
- Refresh token rotation
- Rate limiting (5 login attempts per minute)
- CORS configuration
- SQL injection protection (SQLAlchemy ORM)

## Environment Variables

```env
DATABASE_URL=postgresql://user:pass@localhost/authdb
REDIS_URL=redis://localhost:6379
SECRET_KEY=your-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
```

## Database Schema

```sql
users:
  - id (UUID, primary key)
  - email (unique)
  - hashed_password
  - role (enum: user, trader, admin)
  - is_active
  - created_at
  - last_login

refresh_tokens:
  - id (UUID)
  - user_id (foreign key)
  - token (unique)
  - expires_at
  - revoked

audit_logs:
  - id
  - user_id
  - action
  - ip_address
  - timestamp
```

## Testing

```bash
pytest tests/ -v
```

## Docker Deployment

```bash
docker-compose up -d
```

## Author

**Gabriel Demetrios Lafis**
