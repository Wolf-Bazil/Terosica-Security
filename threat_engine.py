
import hashlib
import re
import json
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum
import numpy as np
from datetime import datetime


class ThreatLevel(Enum):
    CRITICAL = (0.85, 1.0, "CRITICAL")
    HIGH = (0.70, 0.84, "HIGH")
    MEDIUM = (0.50, 0.69, "MEDIUM")
    LOW = (0.25, 0.49, "LOW")
    MINIMAL = (0.0, 0.24, "MINIMAL")


@dataclass
class ThreatScore:
    overall_score: float
    threat_level: ThreatLevel
    indicators: Dict[str, float] = field(default_factory=dict)
    contributing_factors: List[str] = field(default_factory=list)
    confidence: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self):
        return {
            "overall_score": round(self.overall_score, 4),
            "threat_level": self.threat_level.value[2],
            "indicators": {k: round(v, 4) for k, v in self.indicators.items()},
            "contributing_factors": self.contributing_factors,
            "confidence": round(self.confidence, 4),
            "timestamp": self.timestamp,
        }


class PhishingDetectionEngine:
    PHISHING_VECTORS = {
        "urgency_language": {
            "keywords": ["urgent", "immediate", "verify", "confirm", "action", "alert", "suspended", "limited"],
            "weight": 0.25
        },
        "credential_extraction": {
            "keywords": ["verify account", "confirm identity", "update password", "validate credentials"],
            "weight": 0.30
        },
        "suspicious_links": {
            "keywords": ["click here", "verify", "confirm", "update account"],
            "weight": 0.20
        },
        "authority_impersonation": {
            "keywords": ["paypal", "amazon", "apple", "microsoft", "bank", "admin", "support"],
            "weight": 0.25
        }
    }
    
    def analyze(self, subject: str, sender: str, body: str) -> ThreatScore:
        indicators = {}
        
        indicators["urgency_language"] = self._detect_urgency_language(subject + " " + body)
        indicators["credential_extraction"] = self._detect_credential_extraction(body)
        indicators["sender_domain"] = self._analyze_sender_domain(sender)
        indicators["suspicious_links"] = self._detect_suspicious_links(body)
        indicators["authority_impersonation"] = self._detect_authority_impersonation(subject + " " + body)
        
        overall_score = self._calculate_weighted_score(indicators)
        threat_level = self._classify_threat(overall_score)
        
        contributing_factors = []
        for factor, score in indicators.items():
            if score > 0.5:
                contributing_factors.append(f"{factor}: {score:.2%} risk")
        
        return ThreatScore(
            overall_score=overall_score,
            threat_level=threat_level,
            indicators=indicators,
            contributing_factors=contributing_factors,
            confidence=0.92,
        )
    
    def _detect_urgency_language(self, text: str) -> float:
        text_lower = text.lower()
        found = sum(1 for kw in self.PHISHING_VECTORS["urgency_language"]["keywords"] 
                   if kw in text_lower)
        return min(1.0, found * 0.15)
    
    def _detect_credential_extraction(self, text: str) -> float:
        text_lower = text.lower()
        found = sum(1 for kw in self.PHISHING_VECTORS["credential_extraction"]["keywords"] 
                   if kw in text_lower)
        return min(1.0, found * 0.20)
    
    def _analyze_sender_domain(self, sender: str) -> float:
        if "@" not in sender:
            return 0.3
        
        domain = sender.split("@")[1]
        score = 0.0
        
        if any(char in domain for char in ["1", "l", "I", "O", "0", "8", "b"]):
            score += 0.3
        
        if not any(tld in domain for tld in [".com", ".org", ".edu", ".gov", ".co"]):
            score += 0.2
        
        if domain.count(".") > 2:
            score += 0.15
        
        return min(1.0, score)
    
    def _detect_suspicious_links(self, text: str) -> float:
        link_pattern = r'https?://[^\s]+'
        links = re.findall(link_pattern, text)
        if not links:
            return 0.0
        
        suspicious_count = 0
        for link in links:
            if any(substr in link for substr in ["bit.ly", "tinyurl", "shortened"]):
                suspicious_count += 1
            if "@" in link or "%40" in link:
                suspicious_count += 1
        
        return min(1.0, (suspicious_count / len(links)) * 0.6)
    
    def _detect_authority_impersonation(self, text: str) -> float:
        text_lower = text.lower()
        found = sum(1 for kw in self.PHISHING_VECTORS["authority_impersonation"]["keywords"] 
                   if kw in text_lower)
        return min(1.0, found * 0.18)
    
    def _calculate_weighted_score(self, indicators: Dict[str, float]) -> float:
        weights = {
            "urgency_language": 0.15,
            "credential_extraction": 0.30,
            "sender_domain": 0.20,
            "suspicious_links": 0.20,
            "authority_impersonation": 0.15,
        }
        
        score = 0.0
        for key, weight in weights.items():
            score += indicators.get(key, 0) * weight
        
        return min(1.0, score)
    
    def _classify_threat(self, score: float) -> ThreatLevel:
        for level in ThreatLevel:
            if level.value[0] <= score <= level.value[1]:
                return level
        return ThreatLevel.MINIMAL


class PasswordAnalyzer:
    COMMON_PATTERNS = [
        r"^[a-z]+\d+$",
        r"^password\d*$",
        r"^admin\d*$",
        r"^123456",
        r"^qwerty",
        r"^abc123",
    ]
    
    def analyze(self, password: str) -> ThreatScore:
        indicators = {}
        
        indicators["entropy_bits"] = self._calculate_entropy(password)
        indicators["length_score"] = self._analyze_length(password)
        indicators["character_diversity"] = self._analyze_diversity(password)
        indicators["pattern_vulnerability"] = self._detect_common_patterns(password)
        
        strength = self._calculate_strength_score(indicators)
        threat_level = self._classify_password_level(strength)
        
        contributing_factors = []
        if indicators["entropy_bits"] < 40:
            contributing_factors.append("Low entropy")
        if indicators["length_score"] < 0.5:
            contributing_factors.append("Short length")
        if indicators["character_diversity"] < 0.5:
            contributing_factors.append("Limited character variety")
        if indicators["pattern_vulnerability"] > 0.5:
            contributing_factors.append("Common pattern detected")
        
        return ThreatScore(
            overall_score=strength,
            threat_level=threat_level,
            indicators=indicators,
            contributing_factors=contributing_factors,
            confidence=0.95,
        )
    
    def _calculate_entropy(self, password: str) -> float:
        if not password:
            return 0.0
        
        char_counts = {}
        for char in password:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0.0
        for count in char_counts.values():
            p = count / len(password)
            entropy -= p * np.log2(p) if p > 0 else 0
        
        return entropy * len(password)
    
    def _analyze_length(self, password: str) -> float:
        length = len(password)
        if length < 8:
            return 0.2
        elif length < 12:
            return 0.5
        elif length < 16:
            return 0.8
        else:
            return 1.0
    
    def _analyze_diversity(self, password: str) -> float:
        diversity = {
            "upper": any(c.isupper() for c in password),
            "lower": any(c.islower() for c in password),
            "digit": any(c.isdigit() for c in password),
            "special": any(not c.isalnum() for c in password),
        }
        return sum(diversity.values()) / 4.0
    
    def _detect_common_patterns(self, password: str) -> float:
        pattern_risk = 0.0
        password_lower = password.lower()
        
        for pattern in self.COMMON_PATTERNS:
            if re.match(pattern, password_lower):
                pattern_risk = 0.8
                break
        
        if len(set(password)) < len(password) * 0.5:
            pattern_risk = max(pattern_risk, 0.5)
        
        return pattern_risk
    
    def _calculate_strength_score(self, indicators: Dict[str, float]) -> float:
        weights = {
            "entropy_bits": 0.4,
            "length_score": 0.25,
            "character_diversity": 0.25,
            "pattern_vulnerability": -0.1,
        }
        
        score = 0.0
        for key, weight in weights.items():
            value = indicators.get(key, 0)
            score += value * weight
        
        return max(0.0, min(1.0, score))
    
    def _classify_password_level(self, strength: float) -> ThreatLevel:
        for level in ThreatLevel:
            if level.value[0] <= strength <= level.value[1]:
                return level
        return ThreatLevel.MINIMAL


class ProfileVerifier:
    SPOOFING_INDICATORS = {
        "profile_age": {"weight": 0.15},
        "activity_patterns": {"weight": 0.20},
        "image_authenticity": {"weight": 0.25},
        "behavioral_anomalies": {"weight": 0.20},
        "network_analysis": {"weight": 0.20},
    }
    
    def verify(self, profile_data: Dict) -> ThreatScore:
        indicators = {}
        
        age_score = self._analyze_profile_age(profile_data.get("created_at"))
        indicators["profile_age"] = age_score
        
        activity_score = self._analyze_activity(profile_data.get("activity_log", []))
        indicators["activity_patterns"] = activity_score
        
        image_score = self._verify_image(profile_data.get("avatar_url"))
        indicators["image_authenticity"] = image_score
        
        behavior_score = self._detect_anomalies(profile_data)
        indicators["behavioral_anomalies"] = behavior_score
        
        network_score = self._analyze_network(profile_data.get("connections", []))
        indicators["network_analysis"] = network_score
        
        overall_score = self._calculate_authenticity_score(indicators)
        threat_level = self._classify_profile_threat(overall_score)
        
        contributing_factors = []
        for factor, score in indicators.items():
            if score > 0.6:
                contributing_factors.append(f"{factor}: {score:.2%} risk")
        
        return ThreatScore(
            overall_score=overall_score,
            threat_level=threat_level,
            indicators=indicators,
            contributing_factors=contributing_factors,
            confidence=0.88,
        )
    
    def _analyze_profile_age(self, created_at: Optional[str]) -> float:
        if not created_at:
            return 0.8
        
        try:
            created_date = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            age_days = (datetime.utcnow() - created_date).days
            
            if age_days < 1:
                return 0.9
            elif age_days < 7:
                return 0.7
            elif age_days < 30:
                return 0.4
            else:
                return 0.1
        except:
            return 0.5
    
    def _analyze_activity(self, activity_log: List) -> float:
        if not activity_log:
            return 0.7
        
        if len(activity_log) < 10:
            return 0.6
        
        return min(1.0, 0.1 + (len(activity_log) * 0.02))
    
    def _verify_image(self, avatar_url: Optional[str]) -> float:
        if not avatar_url:
            return 0.6
        
        if avatar_url.startswith("http"):
            return 0.2
        
        return 0.4
    
    def _detect_anomalies(self, profile_data: Dict) -> float:
        anomaly_score = 0.0
        
        required_fields = ["username", "email", "bio"]
        missing = sum(1 for field in required_fields if not profile_data.get(field))
        anomaly_score += missing * 0.15
        
        username = profile_data.get("username", "").lower()
        if re.match(r"^user\d+$", username) or re.match(r"^test", username):
            anomaly_score += 0.3
        
        return min(1.0, anomaly_score)
    
    def _analyze_network(self, connections: List) -> float:
        if not connections:
            return 0.5
        
        if len(connections) < 5:
            return 0.6
        
        return min(1.0, 0.1 + (len(connections) * 0.02))
    
    def _calculate_authenticity_score(self, indicators: Dict[str, float]) -> float:
        total = 0.0
        for factor_name, score in indicators.items():
            weight = self.SPOOFING_INDICATORS[factor_name]["weight"]
            total += score * weight
        return min(1.0, total)
    
    def _classify_profile_threat(self, score: float) -> ThreatLevel:
        for level in ThreatLevel:
            if level.value[0] <= score <= level.value[1]:
                return level
        return ThreatLevel.MINIMAL


phishing_engine = PhishingDetectionEngine()
password_analyzer = PasswordAnalyzer()
profile_verifier = ProfileVerifier()
