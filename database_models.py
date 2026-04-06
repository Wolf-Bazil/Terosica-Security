
from datetime import datetime
from typing import Optional, List, Dict
from enum import Enum
import json
from dataclasses import dataclass, asdict, field

class AnalysisType(Enum):
    PHISHING = "phishing_analysis"
    PASSWORD = "password_analysis"
    PROFILE = "profile_verification"
    BATCH = "batch_analysis"

class ThreatLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"

@dataclass
class ThreatAnalysisRecord:
    id: str
    analysis_type: str
    input_data: dict
    threat_score: float
    threat_level: str
    indicators: dict
    risk_factors: List[str]
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    api_key_hash: Optional[str] = None
    user_ip: Optional[str] = None
    
    def to_json(self) -> str:
        return json.dumps(asdict(self))

@dataclass
class AuditLog:
    id: str
    api_key_hash: str
    endpoint: str
    method: str
    request_size: int
    response_size: int
    status_code: int
    latency_ms: float
    success: bool
    error_message: Optional[str] = None
    user_agent: Optional[str] = None
    client_ip: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

@dataclass
class BatchAnalysisJob:
    id: str
    status: str
    items_count: int
    completed_count: int
    analysis_type: str
    results: List[Dict] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None

@dataclass
class ThreatIntelligenceRecord:
    id: str
    threat_type: str
    indicator_value: str
    confidence_score: float
    source: str
    last_seen: str
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

@dataclass
class APIKeyRotation:
    old_key: str
    new_key: str
    rotated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    reason: str = ""

class InMemoryDatabase:
    def __init__(self):
        self.threat_records: List[ThreatAnalysisRecord] = []
        self.audit_logs: List[AuditLog] = []
        self.batch_jobs: List[BatchAnalysisJob] = []
        self.threat_intel: List[ThreatIntelligenceRecord] = []
        self.key_rotations: List[APIKeyRotation] = []
    
    def add_threat_record(self, record: ThreatAnalysisRecord) -> None:
        self.threat_records.append(record)
    
    def add_audit_log(self, log: AuditLog) -> None:
        self.audit_logs.append(log)
    
    def add_batch_job(self, job: BatchAnalysisJob) -> None:
        self.batch_jobs.append(job)
    
    def get_batch_job(self, job_id: str) -> Optional[BatchAnalysisJob]:
        for job in self.batch_jobs:
            if job.id == job_id:
                return job
        return None
    
    def update_batch_job(self, job_id: str, **kwargs) -> None:
        job = self.get_batch_job(job_id)
        if job:
            for key, value in kwargs.items():
                setattr(job, key, value)
    
    def get_threat_records(self, limit: int = 100) -> List[ThreatAnalysisRecord]:
        return self.threat_records[-limit:]
    
    def get_audit_logs(self, api_key_hash: str = None, limit: int = 50) -> List[AuditLog]:
        logs = self.audit_logs
        if api_key_hash:
            logs = [log for log in logs if log.api_key_hash == api_key_hash]
        return logs[-limit:]
    
    def get_statistics(self) -> Dict:
        return {
            "total_threat_records": len(self.threat_records),
            "total_audit_logs": len(self.audit_logs),
            "total_batch_jobs": len(self.batch_jobs),
            "active_batch_jobs": sum(1 for job in self.batch_jobs if job.status == "processing"),
            "threat_intel_entries": len(self.threat_intel),
        }

class ThreatQuery:
    def __init__(self):
        self.db = get_database()
        self.filters = {}
    
    def between_dates(self, start: str, end: str):
        self.filters['date_range'] = (start, end)
        return self
    
    def by_threat_level(self, level: str):
        self.filters['threat_level'] = level
        return self
    
    def by_analysis_type(self, analysis_type: str):
        self.filters['analysis_type'] = analysis_type
        return self
    
    def execute(self) -> List[ThreatAnalysisRecord]:
        results = self.db.threat_records
        
        if 'threat_level' in self.filters:
            results = [r for r in results if r.threat_level == self.filters['threat_level']]
        
        if 'analysis_type' in self.filters:
            results = [r for r in results if r.analysis_type == self.filters['analysis_type']]
        
        if 'date_range' in self.filters:
            start, end = self.filters['date_range']
            results = [r for r in results if start <= r.created_at <= end]
        
        return results

class CacheManager:
    def __init__(self, ttl: int = 3600):
        self.cache: Dict[str, any] = {}
        self.timestamps: Dict[str, datetime] = {}
        self.ttl = ttl
    
    def set(self, key: str, value: any) -> None:
        self.cache[key] = value
        self.timestamps[key] = datetime.utcnow()
    
    def get(self, key: str) -> Optional[any]:
        if key not in self.cache:
            return None
        
        time_diff = (datetime.utcnow() - self.timestamps[key]).total_seconds()
        if time_diff > self.ttl:
            self.delete(key)
            return None
        
        return self.cache[key]
    
    def delete(self, key: str) -> None:
        self.cache.pop(key, None)
        self.timestamps.pop(key, None)
    
    def clear(self) -> None:
        self.cache.clear()
        self.timestamps.clear()
    
    def get_stats(self) -> Dict:
        return {
            "cached_items": len(self.cache),
            "ttl_seconds": self.ttl,
        }

_db_instance = InMemoryDatabase()
_cache = CacheManager()

def get_database() -> InMemoryDatabase:
    return _db_instance

def get_cache() -> CacheManager:
    return _cache
