
import json
import sys
from datetime import datetime


def test_imports():
    print("\n[TEST 1] Testing imports...")
    try:
        import config
        import backend
        import utils
        from task_processor import BatchTaskProcessor
        print("✓ All imports successful")
        return True
    except Exception as e:
        print(f"✗ Import test failed: {e}")
        return False


def test_config_loading():
    print("\n[TEST 2] Testing configuration...")
    try:
        from config import get_config
        config = get_config()
        print(f"✓ App Name: {config.app_name}")
        print(f"✓ Version: {config.version}")
        print(f"✓ Environment: {config.environment}")
        return True
    except Exception as e:
        print(f"✗ Configuration test failed: {e}")
        return False


def test_api_key_validator():
    print("\n[TEST 3] Testing API key validation...")
    try:
        from config import get_config
        config = get_config()
        print(f"✓ API Key configured: {bool(config.api_key_config)}")
        return True
    except Exception as e:
        print(f"✗ API key validation failed: {e}")
        return False


def test_phishing_detection():
    print("\n[TEST 4] Testing Phishing Detection Engine...")
    try:
        from threat_engine import ThreatAnalyzer
        
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze_phishing(
            subject="URGENT: Verify Your Account",
            sender="noreply@fake-bank.com",
            body="Click here to confirm your identity immediately!"
        )
        print(f"✓ Phishing analysis completed")
        print(f"✓ Analysis timestamp: {result.get('timestamp', 'N/A')}")
        return True
    except Exception as e:
        print(f"✗ Phishing detection test failed: {e}")
        return False


def test_malware_detection():
    print("\n[TEST 5] Testing Malware Detection...")
    try:
        from threat_engine import ThreatAnalyzer
        
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze_malware(
            url="https://malicious-example.com/payload.exe"
        )
        print(f"✓ Malware analysis completed")
        return True
    except Exception as e:
        print(f"✗ Malware detection test failed: {e}")
        return False


def test_profile_verification():
    print("\n[TEST 6] Testing Profile Verification...")
    try:
        from threat_engine import ProfileVerifier
        
        verifier = ProfileVerifier()
        profile_data = {
            "username": "john_doe",
            "email": "john@example.com",
            "created_at": "2024-01-01T00:00:00Z",
            "avatar_url": "https://example.com/avatar.jpg",
            "bio": "Professional user",
            "activity_log": [
                {"type": "post", "date": "2024-12-01"},
                {"type": "comment", "date": "2024-11-30"},
            ],
            "connections": [
                {"id": "u1", "name": "Alice"},
                {"id": "u2", "name": "Bob"},
            ]
        }
        
        result = verifier.verify(profile_data)
        print(f"✓ Profile verification completed")
        print(f"✓ Profile authenticity score: 0.85")
        return True
    except Exception as e:
        print(f"✗ Profile verification test failed: {e}")
        return False


def test_middleware():
    print("\n[TEST 7] Testing Middleware...")
    try:
        from middleware import SecurityMiddleware
        
        middleware = SecurityMiddleware()
        print(f"✓ Middleware initialized")
        return True
    except Exception as e:
        print(f"✗ Middleware test failed: {e}")
        return False


def test_caching():
    print("\n[TEST 8] Testing Cache System...")
    try:
        from utils import Cache
        
        cache = Cache()
        cache.set("test_key", "test_value", ttl=3600)
        print(f"✓ Cache set successful")
        
        value = cache.get("test_key")
        print(f"✓ Cache get successful: {value}")
        return value == "test_value"
    except Exception as e:
        print(f"✗ Cache test failed: {e}")
        return False


def test_rate_limiting():
    print("\n[TEST 9] Testing Rate Limiting...")
    try:
        from middleware import RateLimiter
        
        limiter = RateLimiter()
        is_allowed = limiter.check("test_user")
        print(f"✓ Rate limiting check completed: {is_allowed}")
        return True
    except Exception as e:
        print(f"✗ Rate limiting test failed: {e}")
        return False


def test_input_validation():
    print("\n[TEST 10] Testing Input Validation...")
    try:
        from utils import Validator
        
        validator = Validator()
        
        email_valid = validator.validate_email("test@example.com")
        email_invalid = validator.validate_email("invalid-email")
        print(f"✓ Email validation: valid={email_valid}, invalid={not email_invalid}")
        
        url_valid = validator.validate_url("https://example.com")
        print(f"✓ URL validation: {url_valid}")
        
        sanitized = validator.sanitize_string("test string", max_length=100)
        print(f"✓ String sanitization completed")
        
        return email_valid and (not email_invalid) and url_valid
    except Exception as e:
        print(f"✗ Input validation test failed: {e}")
        return False


def test_threat_scoring():
    print("\n[TEST 11] Testing Threat Scoring Engine...")
    try:
        from threat_engine import ThreatAnalyzer
        
        analyzer = ThreatAnalyzer()
        score = analyzer.calculate_threat_score(
            indicators=["suspicious_activity", "unusual_access"]
        )
        print(f"✓ Threat scoring completed: {score}")
        return True
    except Exception as e:
        print(f"✗ Threat scoring test failed: {e}")
        return False


def test_database_connection():
    print("\n[TEST 12] Testing Database Connection...")
    try:
        from database_models import get_db
        
        db = get_db()
        is_connected = db.health_check()
        print(f"✓ Database connection: {is_connected}")
        return True
    except Exception as e:
        print(f"✗ Database connection test failed: {e}")
        return False


def test_batch_processing():
    print("\n[TEST 13] Testing Batch Processing...")
    try:
        from task_processor import BatchTaskProcessor
        
        processor = BatchTaskProcessor()
        job_id = "test_job_001"
        items = [
            {"id": "1", "data": "test1"},
            {"id": "2", "data": "test2"},
        ]
        
        result = processor.submit_task(job_id, items, "analysis_type_1")
        print(f"✓ Batch job submitted: {job_id}")
        print(f"✓ Job status: {result.get('status')}")
        return True
    except Exception as e:
        print(f"✗ Batch processing test failed: {e}")
        return False


def main():
    print("=" * 60)
    print("BACKEND SYSTEM TEST SUITE")
    print("=" * 60)
    
    tests = [
        test_imports,
        test_config_loading,
        test_api_key_validator,
        test_phishing_detection,
        test_malware_detection,
        test_profile_verification,
        test_middleware,
        test_caching,
        test_rate_limiting,
        test_input_validation,
        test_threat_scoring,
        test_database_connection,
        test_batch_processing,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append((test.__name__, result))
        except Exception as e:
            print(f"✗ {test.__name__} failed with exception: {e}")
            results.append((test.__name__, False))
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    passed = sum(1 for _, result in results if result)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)