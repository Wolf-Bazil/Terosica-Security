
from datetime import datetime
from typing import Dict, List, Any
import uuid


class BatchTaskProcessor:
    def __init__(self):
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.results: Dict[str, List[Dict]] = {}

    def submit_task(self, job_id: str, items: List[Dict], analysis_type: str) -> Dict:
        self.jobs[job_id] = {
            "status": "processing",
            "analysis_type": analysis_type,
            "total": len(items),
            "processed": 0,
            "failed": 0,
            "started_at": datetime.utcnow().isoformat(),
        }
        
        results = []
        for idx, item in enumerate(items):
            try:
                result = self._analyze_item(analysis_type, item, job_id)
                results.append(result)
                self.jobs[job_id]["processed"] += 1
            except Exception as e:
                self.jobs[job_id]["failed"] += 1
        
        self.jobs[job_id]["status"] = "completed"
        self.jobs[job_id]["completed_at"] = datetime.utcnow().isoformat()
        self.results[job_id] = results
        return self.jobs[job_id]

    def _analyze_item(self, analysis_type: str, item: Dict, item_id: str) -> Dict:
        return {
            "item_id": item_id,
            "analysis_type": analysis_type,
            "timestamp": datetime.utcnow().isoformat(),
            "data": item
        }

    def get_job_status(self, job_id: str) -> Dict:
        return self.jobs.get(job_id)

    def get_job_results(self, job_id: str) -> List[Dict]:
        return self.results.get(job_id, [])