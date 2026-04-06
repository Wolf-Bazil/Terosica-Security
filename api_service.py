
import uuid
import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from enum import Enum
import time

from threat_engine import (
    phishing_engine,
    password_analyzer,
    profile_verifier,
)
from database_models import (
    ThreatAnalysisRecord,
    BatchAnalysisJob,
    get_database,
    get_cache,
)
from middleware import (
    api_key_validator,
    audit_logger,
)
from utils import (
    logger,
    Validator,
    ResponseFormatter,
    monitor,
    measure_performance,
)


class AnalysisService:
    def __init__(self):
        self.db = get_database()
        self.cache = get_cache()

    def analyze_phishing_email(self, api_key: str, subject: str, sender: str, body: str) -> Dict:
        try:
            if not api_key_validator.validate(api_key):
                return ResponseFormatter.error("Invalid API key", "AUTH_FAILED")

            analysis = phishing_engine.analyze(subject, sender, body)

            key_hash = api_key_validator.get_key_hash(api_key)
            audit_logger.log(key_hash, "PHISHING_ANALYSIS", {"subject": subject, "result": analysis})

            record = ThreatAnalysisRecord(
                analysis_type="phishing",
                api_key_hash=key_hash,
                input_data={"subject": subject, "sender": sender},
                result=analysis,
                timestamp=datetime.utcnow()
            )
            self.db.save_record(record)

            cache_key = f"phishing_{subject}_{sender}"
            self.cache.set(cache_key, analysis, ttl=3600)

            return ResponseFormatter.success(
                data={
                    "threat_score": analysis.get("threat_score", 0),
                    "indicators": analysis.get("indicators", []),
                    "recommendation": analysis.get("recommendation", ""),
                },
                message="Email analysis complete"
            )
        except Exception as e:
            logger.error(f"Phishing analysis error: {str(e)}")
            return ResponseFormatter.error(str(e), "ANALYSIS_ERROR")

    def analyze_password_strength(self, api_key: str, password: str) -> Dict:
        try:
            if not api_key_validator.validate(api_key):
                return ResponseFormatter.error("Invalid API key", "AUTH_FAILED")

            analysis = password_analyzer.analyze(password)

            key_hash = api_key_validator.get_key_hash(api_key)
            audit_logger.log(key_hash, "PASSWORD_ANALYSIS", {"result": analysis})

            record = ThreatAnalysisRecord(
                analysis_type="password",
                api_key_hash=key_hash,
                input_data={"password_length": len(password)},
                result=analysis,
                timestamp=datetime.utcnow()
            )
            self.db.save_record(record)

            return ResponseFormatter.success(
                data={
                    "strength_score": analysis.get("strength_score", 0),
                    "recommendations": analysis.get("recommendations", []),
                    "issues": analysis.get("issues", []),
                },
                message="Password analysis complete"
            )
        except Exception as e:
            logger.error(f"Password analysis error: {str(e)}")
            return ResponseFormatter.error(str(e), "ANALYSIS_ERROR")

    def verify_profile_authenticity(self, api_key: str, profile_data: Dict) -> Dict:
        try:
            if not api_key_validator.validate(api_key):
                return ResponseFormatter.error("Invalid API key", "AUTH_FAILED")

            verification = profile_verifier.verify(profile_data)

            key_hash = api_key_validator.get_key_hash(api_key)
            audit_logger.log(key_hash, "PROFILE_VERIFICATION", {"result": verification})

            record = ThreatAnalysisRecord(
                analysis_type="profile",
                api_key_hash=key_hash,
                input_data={"profile_fields": list(profile_data.keys())},
                result=verification,
                timestamp=datetime.utcnow()
            )
            self.db.save_record(record)

            cache_key = f"profile_{id(profile_data)}"
            self.cache.set(cache_key, verification, ttl=3600)

            return ResponseFormatter.success(
                data={
                    "authenticity_score": verification.get("authenticity_score", 0),
                    "flags": verification.get("flags", []),
                    "assessment": verification.get("assessment", ""),
                },
                message="Profile verification complete"
            )
        except Exception as e:
            logger.error(f"Profile verification error: {str(e)}")
            return ResponseFormatter.error(str(e), "VERIFICATION_ERROR")

    def create_batch_job(self, api_key: str, items: List, analysis_type: str) -> Dict:
        try:
            if not api_key_validator.validate(api_key):
                return ResponseFormatter.error("Invalid API key", "AUTH_FAILED")

            job_id = str(uuid.uuid4())
            key_hash = api_key_validator.get_key_hash(api_key)

            job = BatchAnalysisJob(
                id=job_id,
                api_key_hash=key_hash,
                analysis_type=analysis_type,
                items=items,
                status="PENDING",
                total_items=len(items),
                processed_items=0,
                failed_items=0,
                created_at=datetime.utcnow()
            )
            self.db.save_batch_job(job)

            audit_logger.log(key_hash, "BATCH_JOB_CREATED", {"job_id": job_id, "item_count": len(items)})

            return ResponseFormatter.success(
                data={
                    "job_id": job_id,
                    "status": "PENDING",
                    "total_items": len(items),
                },
                message="Batch job created"
            )
        except Exception as e:
            logger.error(f"Batch job creation error: {str(e)}")
            return ResponseFormatter.error(str(e), "BATCH_ERROR")

    def get_batch_job_status(self, job_id: str) -> Dict:
        try:
            job = self.db.get_batch_job(job_id)

            if not job:
                return ResponseFormatter.error("Job not found", "NOT_FOUND")

            return ResponseFormatter.success(
                data={
                    "job_id": job.id,
                    "status": job.status,
                    "total_items": job.total_items,
                    "processed_items": job.processed_items,
                    "failed_items": job.failed_items,
                    "created_at": job.created_at,
                    "completed_at": job.completed_at,
                },
                message="Job status retrieved"
            )
        except Exception as e:
            logger.error(f"Batch status error: {str(e)}")
            return ResponseFormatter.error(str(e), "BATCH_ERROR")

    def get_analysis_history(self, api_key: str, limit: int = 50) -> Dict:
        try:
            if not api_key_validator.validate(api_key):
                return ResponseFormatter.error("Invalid API key", "AUTH_FAILED")

            key_hash = api_key_validator.get_key_hash(api_key)
            records = self.db.get_analysis_records(key_hash, limit)

            history = [
                {
                    "id": record.id,
                    "analysis_type": record.analysis_type,
                    "timestamp": record.timestamp,
                    "result": record.result,
                }
                for record in records
            ]

            return ResponseFormatter.success(
                data={"history": history, "total_count": len(history)},
                message="Analysis history retrieved"
            )
        except Exception as e:
            logger.error(f"History retrieval error: {str(e)}")
            return ResponseFormatter.error(str(e), "HISTORY_ERROR")

    def get_usage_statistics(self, api_key: str) -> Dict:
        try:
            if not api_key_validator.validate(api_key):
                return ResponseFormatter.error("Invalid API key", "AUTH_FAILED")

            key_hash = api_key_validator.get_key_hash(api_key)
            audit_logs = self.db.get_audit_logs(key_hash)

            stats = {
                "total_requests": len(audit_logs),
                "cache_size": self.cache.get_stats(),
                "database_stats": self.db.get_statistics(),
            }

            return ResponseFormatter.success(
                data=stats,
                message="Usage statistics retrieved"
            )
        except Exception as e:
            logger.error(f"Usage statistics error: {str(e)}")
            return ResponseFormatter.error(str(e), "STATS_ERROR")


analysis_service = AnalysisService()
