import os
import time
import logging
import redis
from fastapi import HTTPException

logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, limit: int = 15, window: int = 60):
        # Allow 15 requests per 60 seconds by default
        self.limit = limit
        self.window = window
        self._in_memory_fallback = {}
        
        redis_host = os.environ.get("REDIS_HOST", "redis")
        redis_port = int(os.environ.get("REDIS_PORT", 6379))
        
        try:
            self.redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
            self.redis_client.ping()
            self.use_redis = True
            logger.info("Connected to Redis for Rate Limiting")
        except Exception as e:
            logger.warning(f"Redis unavailable, falling back to in-memory rate limiting. Error: {e}")
            self.use_redis = False

    def check_rate_limit(self, agent_id: str) -> None:
        """Enforces a fixed-window rate limit for a specific agent identity."""
        current_minute = int(time.time() // self.window)
        key = f"rate_limit:{agent_id}:{current_minute}"
        
        if self.use_redis:
            try:
                current_hits = self.redis_client.incr(key)
                if current_hits == 1:
                    # Set expiry to clear out keys automatically after the window passes
                    self.redis_client.expire(key, self.window + 10)
                    
                if current_hits > self.limit:
                    logger.warning(f"Rate limit exceeded for agent {agent_id}")
                    raise HTTPException(status_code=429, detail="Rate limit exceeded. Too many requests to AI tools.")
                return
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Redis error during rate limiting, failing open: {e}")
                return
                
        # Fallback in-memory logic
        if key not in self._in_memory_fallback:
            # Cleanup old keys to prevent memory leak
            self._in_memory_fallback = {k: v for k, v in self._in_memory_fallback.items() if str(current_minute) in k}
            self._in_memory_fallback[key] = 0
            
        self._in_memory_fallback[key] += 1
        if self._in_memory_fallback[key] > self.limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded. Too many requests to AI tools.")

rate_limiter = RateLimiter(limit=15, window=60)
