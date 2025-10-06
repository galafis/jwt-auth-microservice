"""
JWT Authentication Microservice
Production-ready authentication service with FastAPI
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta
import jwt
import bcrypt
import os

app = FastAPI(
    title="JWT Authentication Microservice",
    description="Production-ready JWT authentication with RBAC",
    version="1.0.0"
)

security = HTTPBearer()

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

# In-memory storage (replace with database in production)
users_db = {}
refresh_tokens_db = {}
blacklist = set()

# Models
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    role: str = "user"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class RefreshRequest(BaseModel):
    refresh_token: str

class User(BaseModel):
    id: str
    email: EmailStr
    role: str
    is_active: bool = True
    created_at: datetime

# Helper functions
def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: dict) -> str:
    """Create JWT refresh token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    """Decode and validate JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    """Get current authenticated user"""
    token = credentials.credentials
    
    # Check if token is blacklisted
    if token in blacklist:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked"
        )
    
    payload = decode_token(token)
    
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type"
        )
    
    user_id = payload.get("sub")
    if user_id not in users_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return users_db[user_id]

def require_role(allowed_roles: List[str]):
    """Dependency to check user role"""
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {allowed_roles}"
            )
        return current_user
    return role_checker

# Routes
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "JWT Authentication Microservice",
        "version": "1.0.0",
        "status": "operational"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "users_count": len(users_db)
    }

@app.post("/auth/register", response_model=User, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegister):
    """Register new user"""
    # Check if user already exists
    if any(u.email == user_data.email for u in users_db.values()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Validate role
    valid_roles = ["user", "trader", "analyst", "admin"]
    if user_data.role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Must be one of: {valid_roles}"
        )
    
    # Create user
    user_id = f"user_{len(users_db) + 1}"
    hashed_password = hash_password(user_data.password)
    
    user = User(
        id=user_id,
        email=user_data.email,
        role=user_data.role,
        is_active=True,
        created_at=datetime.utcnow()
    )
    
    users_db[user_id] = {
        **user.dict(),
        "hashed_password": hashed_password
    }
    
    return user

@app.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    """User login"""
    # Find user
    user = None
    user_id = None
    for uid, u in users_db.items():
        if u["email"] == credentials.email:
            user = u
            user_id = uid
            break
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Verify password
    if not verify_password(credentials.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    # Check if user is active
    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    
    # Create tokens
    token_data = {"sub": user_id, "email": user["email"], "role": user["role"]}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    
    # Store refresh token
    refresh_tokens_db[refresh_token] = {
        "user_id": user_id,
        "created_at": datetime.utcnow()
    }
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshRequest):
    """Refresh access token"""
    # Verify refresh token
    payload = decode_token(request.refresh_token)
    
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type"
        )
    
    # Check if refresh token exists
    if request.refresh_token not in refresh_tokens_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    user_id = payload.get("sub")
    if user_id not in users_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    user = users_db[user_id]
    
    # Create new tokens
    token_data = {"sub": user_id, "email": user["email"], "role": user["role"]}
    new_access_token = create_access_token(token_data)
    new_refresh_token = create_refresh_token(token_data)
    
    # Revoke old refresh token
    del refresh_tokens_db[request.refresh_token]
    
    # Store new refresh token
    refresh_tokens_db[new_refresh_token] = {
        "user_id": user_id,
        "created_at": datetime.utcnow()
    }
    
    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

@app.post("/auth/logout")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Logout (blacklist token)"""
    token = credentials.credentials
    blacklist.add(token)
    return {"message": "Successfully logged out"}

@app.get("/users/me", response_model=User)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current user profile"""
    return current_user

@app.get("/admin/users", response_model=List[User])
async def list_users(current_user: User = Depends(require_role(["admin"]))):
    """List all users (admin only)"""
    return [
        User(
            id=uid,
            email=u["email"],
            role=u["role"],
            is_active=u.get("is_active", True),
            created_at=u["created_at"]
        )
        for uid, u in users_db.items()
    ]

@app.get("/admin/stats")
async def get_stats(current_user: User = Depends(require_role(["admin"]))):
    """Get system statistics (admin only)"""
    return {
        "total_users": len(users_db),
        "active_users": sum(1 for u in users_db.values() if u.get("is_active", True)),
        "active_refresh_tokens": len(refresh_tokens_db),
        "blacklisted_tokens": len(blacklist),
        "roles": {
            role: sum(1 for u in users_db.values() if u["role"] == role)
            for role in ["user", "trader", "analyst", "admin"]
        }
    }

@app.post("/trading/execute")
async def execute_trade(current_user: User = Depends(require_role(["trader", "admin"]))):
    """Execute trade (trader/admin only)"""
    return {
        "message": "Trade executed successfully",
        "user": current_user.email,
        "role": current_user.role,
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
