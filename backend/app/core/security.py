import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional, Any
import bcrypt
import jwt

from app.core.config import settings


class LoginRateLimiter:
    """In-memory sliding window rate limiter for login protection against brute force and DoS."""
    def __init__(self, max_attempts: int = 10, window_seconds: int = 60):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)

    def is_rate_limited(self, key: str) -> bool:
        now = time.time()
        self._attempts[key] = [t for t in self._attempts[key] if now - t < self.window_seconds]
        return len(self._attempts[key]) >= self.max_attempts

    def record_attempt(self, key: str):
        self._attempts[key].append(time.time())

    def clear(self, key: str):
        if key in self._attempts:
            del self._attempts[key]


login_limiter = LoginRateLimiter(max_attempts=10, window_seconds=60)


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def create_access_token(subject: str | Any, role: str, expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "role": role,
    }
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except Exception:
        return None
