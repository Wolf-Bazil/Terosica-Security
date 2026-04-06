
import re
import logging
import json
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
from functools import wraps
import hashlib

class APIError(Exception):
    def __init__(self, message: str = "API Error", status_code: int = 400, details: Dict = None):
        super().__init__(message)
        self.status_code = status_code
        self.details = details or {}
    
    def to_dict(self) -> Dict:
        return {
            "error": str(self),
            "status_code": self.status_code,
            "details": self.details,
            "timestamp": datetime.utcnow().isoformat(),
        }

class Validator:
    @staticmethod
    def validate_email(email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_url(url: str) -> bool:
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return re.match(pattern, url) is not None
    
    @staticmethod
    def validate_api_key(api_key: str) -> bool:
        return api_key.startswith("sk-or-v1-") and len(api_key) > 20
    
    @staticmethod
    def sanitize_string(text: str, max_length: int = 1000) -> str:
        return text[:max_length].strip()
    
    @staticmethod
    def validate_required_fields(data: Dict, required_keys: List[str]) -> bool:
        return all(key in data for key in required_keys)

class StringUtils:
    @staticmethod
    def extract_emails(text: str) -> List[str]:
        pattern = r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        return re.findall(pattern, text)
    
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        pattern = r'https?://[^\s]+'
        return re.findall(pattern, text)
    
    @staticmethod
    def extract_domains(text: str) -> List[str]:
        urls = StringUtils.extract_urls(text)
        domains = []
        for url in urls:
            parts = url.split('/')
            if len(parts) > 2:
                domains.append(parts[2])
        return domains
    
    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return StringUtils.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    @staticmethod
    def string_similarity(s1: str, s2: str) -> float:
        distance = StringUtils.levenshtein_distance(s1, s2)
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 1.0
        return 1.0 - (distance / max_len)

class HashUtils:
    @staticmethod
    def sha256(data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def md5(data: str) -> str:
        return hashlib.md5(data.encode()).hexdigest()
    
    @staticmethod
    def generate_checksum(data: Dict) -> str:
        data_str = json.dumps(data, sort_keys=True)
        return HashUtils.sha256(data_str)

class PerformanceMonitor:
    def __init__(self):
        self.metrics = {}
    
    def record_operation(self, operation: str, duration_ms: float) -> None:
        if operation not in self.metrics:
            self.metrics[operation] = []
        self.metrics[operation].append(duration_ms)
    
    def get_statistics(self, operation: str) -> Dict:
        if operation not in self.metrics or not self.metrics[operation]:
            return {}
        
        times = self.metrics[operation]
        return {
            "operation": operation,
            "count": len(times),
            "avg_ms": sum(times) / len(times),
            "min_ms": min(times),
            "max_ms": max(times),
            "total_ms": sum(times),
        }

class ResponseFormatter:
    @staticmethod
    def success(data: Any = None, message: str = "Success", **kwargs) -> Dict:
        return {
            "success": True,
            "message": message,
            "data": data,
            **kwargs
        }
    
    @staticmethod
    def error(message: str = "Error", error_code: str = "ERROR", **kwargs) -> Dict:
        return {
            "success": False,
            "error": message,
            "error_code": error_code,
            "timestamp": datetime.utcnow().isoformat(),
            **kwargs,
        }
    
    @staticmethod
    def paginated(items: List, page: int = 1, page_size: int = 10, total: int = None) -> Dict:
        start = (page - 1) * page_size
        end = start + page_size
        
        return {
            "success": True,
            "data": items[start:end],
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": total or len(items),
                "has_next": end < (total or len(items)),
            }
        }

logger = logging.getLogger("terosica")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

monitor = PerformanceMonitor()
