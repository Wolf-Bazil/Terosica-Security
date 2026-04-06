from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import sys
import os
import re

try:
    from config import get_config, FeatureFlags, THREAT_PATTERNS
    from threat_engine import phishing_engine, password_analyzer, profile_verifier
    from database_models import get_database, get_cache, ThreatAnalysisRecord
    from middleware import (
        require_api_key, 
        require_rate_limit, 
        log_audit_trail,
        api_key_validator,
        rate_limiter,
        audit_logger,
    )
    from api_service import analysis_service
    from utils import logger, ResponseFormatter, monitor, Validator
except ImportError as e:
    print(f"ERROR: Failed to import modules: {e}")
    sys.exit(1)

app = Flask(__name__)
CORS(app)

config = get_config()
app.config["SECRET_KEY"] = config.security.secret_key
app.config["JSON_SORT_KEYS"] = False
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = True

db = get_database()
cache = get_cache()
validator = Validator()

logger.info("Backend initialized", version=config.version, api_version=config.api_version)

@app.errorhandler(400)
def bad_request(error):
    return ResponseFormatter.error("Bad request", "BAD_REQUEST"), 400

@app.errorhandler(401)
def unauthorized(error):
    return ResponseFormatter.error("Unauthorized", "UNAUTHORIZED"), 401

@app.errorhandler(404)
def not_found(error):
    return ResponseFormatter.error("Resource not found", "NOT_FOUND"), 404

@app.errorhandler(429)
def rate_limited(error):
    return ResponseFormatter.error("Rate limit exceeded", "RATE_LIMITED"), 429

@app.errorhandler(500)
def internal_error(error):
    logger.error("Internal server error", error=str(error))
    return ResponseFormatter.error("Internal server error", "INTERNAL_ERROR"), 500

@app.route('/', methods=['GET'])
def index():
    return ResponseFormatter.success(
        data={"app": config.app_name, "version": config.version},
        message="API Backend"
    )

@app.route('/health', methods=['GET'])
def health_check():
    return ResponseFormatter.success(
        data={"status": "healthy", "version": config.version},
        message="System operational"
    ), 200

@app.route('/status', methods=['GET'])
def status():
    return ResponseFormatter.success(
        data={
            "status": "operational",
            "version": config.version,
            "environment": config.environment,
            "cache_stats": cache.get_stats(),
            "database_stats": db.get_statistics(),
        },
        message="System status"
    )

@app.route('/api/v2/phishing/analyze', methods=['POST'])
@require_api_key
@require_rate_limit
@log_audit_trail
def analyze_phishing_email(api_key=None):
    try:
        data = request.get_json()
        
        if not data:
            return ResponseFormatter.error("Request body required"), 400
        
        subject = data.get("subject", "")
        sender = data.get("sender", "")
        body = data.get("body", "")
        
        if not all([subject, sender, body]):
            return ResponseFormatter.error("Missing required fields: subject, sender, body"), 400
        
        result = analysis_service.analyze_phishing_email(api_key, subject, sender, body)
        
        logger.info("Phishing analysis completed", 
                   api_key_hash=api_key_validator.get_key_hash(api_key),
                   threat_score=result.get("data", {}).get("overall_score"))
        
        return result, 200
        
    except Exception as e:
        logger.error("Phishing analysis endpoint error", error=str(e))
        return ResponseFormatter.error(str(e), "ANALYSIS_ERROR"), 500

@app.route('/api/v2/credentials/score', methods=['POST'])
@require_api_key
@require_rate_limit
@log_audit_trail
def analyze_password_strength(api_key=None):
    try:
        data = request.get_json()
        
        if not data:
            return ResponseFormatter.error("Request body required"), 400
        
        password = data.get("password")
        
        if not password:
            return ResponseFormatter.error("Password field required"), 400
        
        result = analysis_service.analyze_password_strength(api_key, password)
        
        logger.info("Password analysis completed",
                   api_key_hash=api_key_validator.get_key_hash(api_key))
        
        return result, 200
        
    except Exception as e:
        logger.error("Password analysis endpoint error", error=str(e))
        return ResponseFormatter.error(str(e), "ANALYSIS_ERROR"), 500

@app.route('/api/v2/profiles/verify', methods=['POST'])
@require_api_key
@require_rate_limit
@log_audit_trail
def verify_profile_authenticity(api_key=None):
    try:
        data = request.get_json()
        
        if not data:
            return ResponseFormatter.error("Request body required"), 400
        
        result = analysis_service.verify_profile_authenticity(api_key, data)
        
        logger.info("Profile verification completed",
                   api_key_hash=api_key_validator.get_key_hash(api_key))
        
        return result, 200
        
    except Exception as e:
        logger.error("Profile verification endpoint error", error=str(e))
        return ResponseFormatter.error(str(e), "ANALYSIS_ERROR"), 500

@app.route('/api/v2/batch/submit', methods=['POST'])
@require_api_key
@require_rate_limit
@log_audit_trail
def submit_batch_job(api_key=None):
    try:
        data = request.get_json()
        
        if not data:
            return ResponseFormatter.error("Request body required"), 400
        
        analysis_type = data.get("analysis_type")
        items = data.get("items", [])
        
        if not analysis_type or not items:
            return ResponseFormatter.error("Missing: analysis_type, items"), 400
        
        result = analysis_service.create_batch_job(api_key, items, analysis_type)
        
        logger.info("Batch job submitted",
                   api_key_hash=api_key_validator.get_key_hash(api_key),
                   job_count=len(items))
        
        return result, 201
        
    except Exception as e:
        logger.error("Batch submission endpoint error", error=str(e))
        return ResponseFormatter.error(str(e), "BATCH_ERROR"), 500

@app.route('/api/v2/batch/<job_id>/status', methods=['GET'])
@require_api_key
@log_audit_trail
def get_batch_status(job_id, api_key=None):
    try:
        limit = request.args.get('limit', 50, type=int)
        limit = min(limit, 100)
        
        result = analysis_service.get_analysis_history(api_key, limit=limit)
        return result, 200
    except Exception as e:
        logger.error("History endpoint error", error=str(e))
        return ResponseFormatter.error(str(e), "HISTORY_ERROR"), 500

@app.route('/api/v2/stats', methods=['GET'])
@require_api_key
@log_audit_trail
def get_usage_stats(api_key=None):
    try:
        stats = {}
        for operation in ["phishing_analysis", "password_analysis", "profile_verification"]:
            perf = monitor.get_statistics(operation)
            if perf:
                stats[operation] = perf
        
        return ResponseFormatter.success(data=stats, message="Performance metrics"), 200
    except Exception as e:
        return ResponseFormatter.error(str(e), "METRICS_ERROR"), 500

@app.route('/api/v2/config/features', methods=['GET'])
@require_api_key
def get_feature_flags(api_key=None):
    try:
        return ResponseFormatter.success(data=THREAT_PATTERNS, message="Threat patterns"), 200
    except Exception as e:
        return ResponseFormatter.error(str(e)), 500

@app.route('/api/v2/audit/log', methods=['GET'])
@require_api_key
def get_audit_log(api_key=None):
    try:
        db_stats = db.get_statistics()
        
        return ResponseFormatter.success(
            data={
                "total_threat_records": db_stats["total_threat_records"],
                "threat_intel_entries": db_stats["threat_intel_entries"],
                "last_updated": "2024-12-01T00:00:00Z",
            },
            message="Threat database info"
        ), 200
    except Exception as e:
        return ResponseFormatter.error(str(e)), 500

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Terosica AI Backend')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--workers', type=int, default=1, help='Number of workers')
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print(f"  Terosica AI - Security Intelligence Platform v{config.version}")
    print("="*70)
    print(f"  Status: RUNNING")
    print(f"  Environment: {config.environment.upper()}")
    print(f"  Debug Mode: {'ON' if args.debug else 'OFF'}")
    print(f"  Workers: {args.workers}")
    print(f"  Database: {config.database.host}:{config.database.port}")
    print(f"  Redis: {config.redis.host}:{config.redis.port}")
    print("="*70)
    print(f"  API Key: {THREAT_PATTERNS.get('api_key', 'sk-or-v1-...')[:20]}...")
    print("="*70)
    print(f"\n  Starting Flask server at http://{args.host}:{args.port}")
    print(f"  → Health check: http://{args.host}:{args.port}/health")
    print(f"  → Docs: http://{args.host}:{args.port}/api/v2")
    print(f"  → Status: http://{args.host}:{args.port}/status\n")
    
    try:
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug,
            use_reloader=False,
        )
    except KeyboardInterrupt:
        print("\n\nServer shutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        logger.error("Fatal error", error=str(e))
        sys.exit(1)

PHISHING_CONTENT_URGENCY = [
    'urgent', 'immediately', 'action required', 'act now', 'hurry',
    'limited time', 'time sensitive', 'deadline', 'expires', 'expiration',
    'confirm now', 'verify account', 'validate', 'reactivate', 'suspended',
    'locked', 'blocked', 'urgent action', 'immediate action', 'asap',
    'critical', 'alert', 'security alert', 'unusual activity', 'suspicious',
    'compromised', 'breach', 'unauthorized access', 'risk', 'danger',
]

PHISHING_CREDENTIAL_KEYWORDS = [
    'username', 'password', 'login', 'account', 'credentials', 'pin',
    'social security', 'ssn', 'credit card', 'card number', 'cvv',
    'bank account', 'routing number', 'swift', 'iban', 'financial info',
    'tax id', 'mother maiden name', 'date of birth', 'email', 'phone',
    'address', 'verify identity', 'confirm details', 'update information',
]

PHISHING_PRIZE_KEYWORDS = [
    'you won', 'you have won', 'congratulations', 'claim prize', 'free money',
    'inheritance', 'lucky', 'selected', 'chosen', 'winner',
    'million dollars', 'million pound', 'awarded', 'winning ticket',
    'lottery', 'sweepstakes', 'giveaway', 'jackpot', 'grand prize',
    'compensation fund', 'beneficiary', 'next of kin', 'deceased estate',
    'dormant account funds', 'unclaimed funds', 'unclaimed money',
    'government grant', 'free grant', 'free cash', 'bitcoin reward',
    'crypto reward', 'gift card', 'amazon gift', 'walmart gift',
    'apple gift card', 'google play', 'steam gift',
]

PHISHING_MALICIOUS_EXTENSIONS = [
    '.exe', '.zip', '.rar', '.scr', '.bat', '.cmd', '.vbs', '.js',
    '.jar', '.msi', '.dmg', '.app', '.apk', '.deb', '.rpm',
    '.ps1', '.hta', '.lnk', '.iso', '.img', '.7z', '.cab',
    '.dll', '.sys', '.com', '.pif', '.reg', '.inf', '.wsh',
    '.wsf', '.xls', '.xlsm', '.doc', '.docm', '.ppt', '.pptm',
]

TYPOSQUAT_DOMAINS = [
    'gmial.com', 'gmai.com', 'gogle.com', 'goggle.com', 'gooogle.com',
    'googl.com', 'goolge.com', 'google.co', 'g00gle.com',
    'yahooo.com', 'yaho.com', 'yhaoo.com', 'yahho.com', 'yahoo.co',
    'hotmial.com', 'hotmai.com', 'hotmal.com', 'hotmall.com',
    'microsft.com', 'micros0ft.com', 'microsoft.co',
    'outlok.com', 'outook.com', 'outlook.co',
    'amazom.com', 'amaz0n.com', 'arnazon.com', 'amazonn.com',
    'amazon.co', 'anazon.com', 'amozon.com',
    'aplle.com', 'aple.com', 'appl.com', 'appie.com', 'apple.co',
    'paypa1.com', 'paypall.com', 'paypa.com', 'paypol.com',
    'paypal.co', 'pay-pal.com', 'paypa1.net',
    'wellsfarg0.com', 'wellsfarg.com', 'chas.com', 'bnak.com',
    'bankofamerica.co', 'citibanck.com',
    'faceb0ok.com', 'facebok.com', 'facbook.com', 'facebook.co',
    'twiter.com', 'twittr.com', 'twitter.co',
    'instagran.com', 'instagram.co', 'lnkedin.com', 'linkedln.com',
    'dropb0x.com', 'netfl1x.com', 'netfix.com', 'netflix.co',
    'spotif.com', 'spotify.co',
]

SUSPICIOUS_SENDER_DOMAINS = [
    'mail.', 'smtp.', 'temp', 'throwaway', 'mailinator.com',
    'guerrillamail.com', 'yopmail.com', 'trashmail.com',
    'fakeinbox.com', 'sharklasers.com', 'guerrillamailblock.com',
    'grr.la', 'spam4.me', 'maildrop.cc', 'getairmail.com',
    'tempr.email', 'dispostable.com', '10minutemail.com',
    'tempmail.com', 'throwam.com', '33mail.com', 'discard.email',
    'mailnull.com', 'spamgourmet.com', 'spamgourmet.net',
    'pookmail.com', 'anonbox.net', 'owlpic.com',
    'mail-temporaire.fr', 'jetable.fr.nf',
]

SUSPICIOUS_SENDER_PATTERNS = [
    'noreply', 'no-reply', 'donotreply', 'do-not-reply',
    'alerts@', 'notifications@', 'security@', 'support@',
    'service@', 'info@', 'admin@', 'account@',
    'billing@', 'payment@', 'invoice@',
    'helpdesk@', 'help@', 'contact@',
]

SUSPICIOUS_URL_PATTERNS = [
    'phishing', 'malware', 'admin', 'login', 'verify', 'confirm',
    'secure', 'security', 'account', 'update', 'signin', 'sign-in',
    'auth', 'authenticate', 'validation', 'validate',
    'password', 'reset', 'recover', 'unlock', 'unblock',
    'suspend', 'restore', 'reactivate', 'reactivation',
    'click', 'redirect', 'forward', 'track', 'go.php',
    'click.php', 'redirect.php', 'gate.php', 'out.php',
    'url=', 'link=', 'goto=', 'target=', 'dest=',
    'paypal', 'ebay', 'amazon', 'apple', 'microsoft',
    'google', 'facebook', 'netflix', 'bank',
    'irs.gov-', '-irs.gov', 'paypal-', '-paypal',
]

SHORTENED_URL_SERVICES = [
    'bit.ly', 'tinyurl.com', 'ow.ly', 't.co', 'goo.gl',
    'short.io', 'rebrand.ly', 'cutt.ly', 'shorte.st',
    'adf.ly', 'bc.vc', 'sh.st', 'linkbucks.com',
    'ouo.io', 'clk.sh', 'soo.gd', 'ai7.net',
    'tgr.ph', 'clicky.me', 'budurl.com', 'short.link',
    'tiny.cc', 'is.gd', 'v.gd', 'u.to',
    'qr.ae', 'vzturl.com', 'post.ly', 'prettylinkpro.com',
]

IMPERSONATED_BRANDS = {
    'paypal': 'paypal.com',
    'amazon': 'amazon.com',
    'apple': 'apple.com',
    'microsoft': 'microsoft.com',
    'google': 'google.com',
    'facebook': 'facebook.com',
    'instagram': 'instagram.com',
    'netflix': 'netflix.com',
    'dropbox': 'dropbox.com',
    'linkedin': 'linkedin.com',
    'twitter': 'twitter.com',
    'ebay': 'ebay.com',
    'bank of america': 'bankofamerica.com',
    'wells fargo': 'wellsfargo.com',
    'chase': 'chase.com',
    'citibank': 'citi.com',
    'american express': 'americanexpress.com',
    'visa': 'visa.com',
    'mastercard': 'mastercard.com',
    'irs': 'irs.gov',
    'usps': 'usps.com',
    'fedex': 'fedex.com',
    'ups': 'ups.com',
    'dhl': 'dhl.com',
    'docusign': 'docusign.com',
    'zoom': 'zoom.us',
    'spotify': 'spotify.com',
    'adobe': 'adobe.com',
    'norton': 'norton.com',
    'mcafee': 'mcafee.com',
    'steam': 'steampowered.com',
    'coinbase': 'coinbase.com',
    'binance': 'binance.com',
}

SUSPICIOUS_BIO_KEYWORDS = [
    'click', 'dm for', 'dm me', 'link in bio', 'swipe up', 'buy now',
    'free money', 'make money', 'earn money', 'work from home',
    'passive income', 'financial freedom', 'investment opportunity',
    'get rich', 'quick money', 'fast cash', 'easy money',
    'crypto trader', 'forex trader', 'bitcoin trader', 'fx trader',
    'profit daily', 'profits', 'guaranteed returns', 'guaranteed income',
    'join my team', 'join us', 'sign up', 'register now',
    'limited spots', 'exclusive access', 'vip access', 'early access',
    'discount code', 'promo code', 'coupon code',
    'model', 'escort', 'adult content', 'onlyfans', 'nsfw',
    'sugar', 'dating', 'meet girls', 'meet men', 'meet singles',
    'lonely', 'looking for fun', 'message me', 'chat with me',
    'call me', 'text me', 'whatsapp me', 'telegram me',
    'love life', 'nature lover', 'music lover', 'food lover',
    'travel lover', 'dog lover', 'cat lover',
    'just joined', 'new here', 'exploring',
    'nft', 'nft artist', 'crypto', 'web3', 'defi', 'metaverse',
    'blockchain', 'token', 'airdrop', 'mint', 'hodl',
    'follow for follow', 'f4f', 'l4l', 'like for like',
    'follow back', 'gain followers', 'get followers', 'buy followers',
]

SUSPICIOUS_USERNAME_PATTERNS = [
    r'\d{4,}$',
    r'^[a-z]+\d{4,}',
    r'_+\d+$',
    r'^user\d+',
    r'^account\d+',
    r'[_]{2,}',
    r'\d{6,}',
    r'^[a-z]{1,3}\d{5,}',
    r'bot$',
    r'^bot',
    r'spam',
    r'fake',
    r'temp\d*',
    r'test\d*',
    r'null\d*',
    r'admin\d*',
    r'official\d*',
    r'verified\d*',
    r'real[_\-]?\w+',
    r'\w+_[xX]{2,}',
    r'[A-Z]{5,}',
    r'[aeiou]{0}[bcdfghjklmnpqrstvwxyz]{8,}',
]

SUBJECT_KEYWORD_WEIGHTS = {
    'high': {
        'keywords': [
            'account suspended', 'account locked', 'account disabled', 'account terminated',
            'account compromised', 'account hacked', 'account breached',
            'unauthorized access', 'unauthorized login', 'suspicious login',
            'verify account', 'verify identity', 'verify now', 'verify email',
            'confirm account', 'confirm identity', 'confirm now',
            'password expired', 'password reset', 'update password',
            'immediate action', 'action required', 'urgent', 'act now',
            'final notice', 'final warning', 'last chance',
            'account will be closed', 'suspended', 'access suspended',
            'security breach', 'breach detected', 'security alert',
            'click here', 'click below', 'click the link',
            'you won', 'claim your prize', 'lottery winner', 'lucky winner',
            'refund approved', 'tax refund', 'irs refund', 'hmrc refund',
            'delivery failed', 'package on hold', 'missed delivery',
            'payment failed', 'payment declined', 'billing issue',
            'invoice attached', 'invoice due',
        ],
        'per_hit': 12,
        'cap': 48,
    },
    'medium': {
        'keywords': [
            'verify', 'confirm', 'validate', 'update account', 'update required',
            'update billing', 'update payment', 'update details', 'update credentials',
            'unusual activity', 'suspicious activity', 'new login detected',
            'new device detected', 'login attempt', 'failed login',
            'security warning', 'security notice', 'security update',
            'password change required', 'expires today', 'expiring soon',
            'time sensitive', 'deadline', 'respond immediately',
            'refund', 'refund pending', 'payment pending', 'payment required',
            'outstanding balance', 'overdue payment', 'wire transfer', 'fund transfer',
            'credit card', 'debit card', 'card declined', 'card expired',
            'bank alert', 'bank notice',
            'claim your reward', 'claim now', 'free gift', 'free money',
            'congratulations', 'winner', 'winning',
            'payroll', 'direct deposit', 'w2', 'w-2', 'tax document', '1099',
            'important notice', 'important alert', 'important update',
            'limited time', 'limited offer', 'exclusive offer',
        ],
        'per_hit': 7,
        'cap': 28,
    },
    'low': {
        'keywords': [
            'important', 'notice', 'notification', 'alert', 'reminder',
            'package', 'parcel', 'delivery', 'shipment', 'tracking',
            'usps', 'fedex', 'ups', 'dhl', 'royal mail',
            'hr update', 'hr notice', 'employee benefit', 'open enrollment',
            'invoice', 'read this', 'read now', 'request',
        ],
        'per_hit': 4,
        'cap': 12,
    },
}

@app.route('/api/phishing/analyze', methods=['POST'])
def analyze_phishing():
    try:
        from urllib.parse import urlparse

        data = request.json
        subject_raw = data.get('subject', '')
        sender_raw  = data.get('sender', '')
        content_raw = data.get('content', '')
        urls_raw    = data.get('urls', '')

        subject = subject_raw.lower()
        sender  = sender_raw.lower()
        content = content_raw.lower()
        urls    = urls_raw.lower()

        risk_score = 0
        indicators = []
        recommendations = []

        danger_sections = set()

        def add_score(points):
            nonlocal risk_score
            risk_score += points

        subject_total = 0

        for tier_name, tier in SUBJECT_KEYWORD_WEIGHTS.items():
            tier_hits = [k for k in tier['keywords'] if k in subject]
            if tier_hits:
                contribution = min(len(tier_hits) * tier['per_hit'], tier['cap'])
                subject_total += contribution
                severity = 'danger' if tier_name == 'high' else 'warning'
                indicators.append({
                    'type': severity,
                    'title': f'{"High" if tier_name == "high" else "Moderate" if tier_name == "medium" else "Low"}-Risk Subject Keywords',
                    'desc': f'Subject contains: {", ".join(tier_hits[:6])}'
                })

        if subject_total > 0:
            add_score(subject_total)
            danger_sections.add('subject')

        stripped = subject_raw.strip()
        if stripped and stripped == stripped.upper() and len(stripped) > 5 and stripped.replace(' ', '').isalpha():
            add_score(10)
            indicators.append({'type': 'warning', 'title': 'ALL CAPS Subject Line',
                                'desc': 'All-caps subjects are a hallmark of spam and phishing attempts'})
            danger_sections.add('subject')

        if re.search(r'[!?]{2,}', subject_raw):
            add_score(8)
            indicators.append({'type': 'warning', 'title': 'Excessive Punctuation in Subject',
                                'desc': 'Multiple !! or ?? create false urgency — common phishing tactic'})
            danger_sections.add('subject')

        if not subject.strip():
            add_score(8)
            indicators.append({'type': 'warning', 'title': 'Empty Subject Line',
                                'desc': 'Legitimate emails almost always have a descriptive subject'})

        sender_domain = ''
        if sender and '@' in sender:
            sender_domain = sender.split('@')[1].strip()

            matched_disposable = [d for d in SUSPICIOUS_SENDER_DOMAINS if d in sender_domain]
            if matched_disposable:
                add_score(35)
                indicators.append({'type': 'danger', 'title': 'Disposable / Throwaway Email Domain',
                                    'desc': f'Sender uses a known temporary email provider — virtually never legitimate'})
                danger_sections.add('sender')

            if sender_domain in TYPOSQUAT_DOMAINS:
                add_score(40)
                indicators.append({'type': 'danger', 'title': 'Confirmed Domain Typosquat',
                                    'desc': f'"{sender_domain}" is a known lookalike of a legitimate domain'})
                danger_sections.add('sender')

            for brand, legit_domain in IMPERSONATED_BRANDS.items():
                legit_root = legit_domain.split('.')[0]
                if legit_root in sender_domain and legit_domain != sender_domain:
                    add_score(30)
                    indicators.append({'type': 'danger', 'title': f'Sender Domain Spoofs {brand.title()}',
                                        'desc': f'Domain "{sender_domain}" contains "{legit_root}" but is NOT {legit_domain} — spoofing attempt'})
                    danger_sections.add('sender')
                    break

            matched_patterns = [p for p in SUSPICIOUS_SENDER_PATTERNS if sender.startswith(p) or f'{p}@' in sender]
            if matched_patterns:
                add_score(10)
                indicators.append({'type': 'warning', 'title': 'Generic Automated Sender',
                                    'desc': f'Sender prefix "{matched_patterns[0]}" is typical of automated bulk senders'})

            if re.search(r'\d{5,}', sender_domain):
                add_score(18)
                indicators.append({'type': 'danger', 'title': 'Randomly Generated Sender Domain',
                                    'desc': f'Domain "{sender_domain}" contains a long number sequence — hallmark of throwaway infrastructure'})
                danger_sections.add('sender')

            parts = sender_domain.split('.')
            if len(parts) > 3:
                add_score(15)
                indicators.append({'type': 'warning', 'title': 'Deep Subdomain in Sender',
                                    'desc': f'"{sender_domain}" has {len(parts)} domain levels — common spoofing technique'})
                danger_sections.add('sender')

            free_webmail = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com', 'live.com', 'msn.com']
            security_subject_terms = ['security', 'alert', 'verify', 'account', 'suspend', 'unusual', 'unauthorized', 'breach']
            if sender_domain in free_webmail and any(t in subject for t in security_subject_terms):
                add_score(25)
                indicators.append({'type': 'danger', 'title': 'Security Alert from Free Webmail Account',
                                    'desc': f'Companies never send security alerts from {sender_domain} — this is impersonation'})
                danger_sections.add('sender')

        else:
            add_score(10)
            indicators.append({'type': 'warning', 'title': 'Missing or Malformed Sender',
                                'desc': 'No valid sender email address provided — legitimate emails always have one'})

        if content:
            urgency_hits = [p for p in PHISHING_CONTENT_URGENCY if p in content]
            if urgency_hits:
                urgency_score = min(len(urgency_hits) * 14, 56)
                add_score(urgency_score)
                indicators.append({'type': 'danger', 'title': f'Urgency / Pressure Tactics ({len(urgency_hits)} instance{"s" if len(urgency_hits)>1 else ""})',
                                    'desc': f'Pressure language found: "{urgency_hits[0]}"' + (f' and {len(urgency_hits)-1} more' if len(urgency_hits) > 1 else '')})
                danger_sections.add('content')

            cred_hits = [p for p in PHISHING_CREDENTIAL_KEYWORDS if p in content]
            if cred_hits:
                cred_score = min(len(cred_hits) * 16, 64)
                add_score(cred_score)
                indicators.append({'type': 'danger', 'title': f'Credential / PII Harvesting ({len(cred_hits)} field{"s" if len(cred_hits)>1 else ""})',
                                    'desc': f'Requests sensitive data: {", ".join(cred_hits[:4])}'})
                danger_sections.add('content')

            prize_hits = [p for p in PHISHING_PRIZE_KEYWORDS if p in content]
            if prize_hits:
                add_score(min(len(prize_hits) * 15, 45))
                indicators.append({'type': 'danger', 'title': 'Prize / Lottery Scam Language',
                                    'desc': f'Classic scam lure: "{prize_hits[0]}"'})
                danger_sections.add('content')

            attach_words = ['attached', 'attachment', 'download', 'open file', 'extract archive',
                            'see attached', 'find attached', 'please open', 'open the file',
                            'run the file', 'execute', 'install']
            if any(k in content for k in attach_words):
                bad_ext_hits = [ext for ext in PHISHING_MALICIOUS_EXTENSIONS if ext in content]
                if bad_ext_hits:
                    add_score(35)
                    indicators.append({'type': 'danger', 'title': 'Malicious Attachment Indicated',
                                        'desc': f'References dangerous file type(s): {", ".join(bad_ext_hits)}'})
                    danger_sections.add('content')
                else:
                    add_score(10)
                    indicators.append({'type': 'warning', 'title': 'Attachment Reference',
                                        'desc': 'Email references a downloadable file — verify before opening'})

            if sender_domain:
                brand_hits = []
                for brand, legit_domain in IMPERSONATED_BRANDS.items():
                    if brand in content and legit_domain not in sender_domain:
                        brand_hits.append(brand.title())
                if brand_hits:
                    impersonation_score = min(len(brand_hits) * 18, 54)
                    add_score(impersonation_score)
                    indicators.append({'type': 'danger', 'title': f'Brand Impersonation: {", ".join(brand_hits[:3])}',
                                        'desc': f'Mentions {", ".join(brand_hits[:3])} but sender domain ({sender_domain}) does not match'})
                    danger_sections.add('content')

            grammar_flags = [
                'dear customer', 'dear user', 'dear account holder', 'dear valued customer',
                'dear valued member', 'dear member', 'dear client', 'dear beneficiary',
                'kindly click', 'kindly verify', 'kindly provide', 'kindly send',
                'do the needful', 'revert back', 'revert to us',
                'i am contacting you', 'i want to contact', 'this mail is to inform',
                'i have a transaction', 'business proposal', 'strictly confidential',
                'mutual benefit', 'god willing', 'please note that',
                'i got your contact', 'i came across your profile',
            ]
            grammar_hits = [g for g in grammar_flags if g in content]
            if grammar_hits:
                add_score(min(len(grammar_hits) * 10, 30))
                indicators.append({'type': 'warning', 'title': f'Suspicious / Non-Native Phrasing ({len(grammar_hits)} instance{"s" if len(grammar_hits)>1 else ""})',
                                    'desc': f'Phrasing typical of scam templates: "{grammar_hits[0]}"'})
                danger_sections.add('content')

            scam_419 = [
                'nigerian prince', 'prince of nigeria', 'barrister', 'attorney at law',
                'deceased client', 'next of kin', 'secret funds', 'confidential transfer',
                '% of the funds', '% of the total', 'partnership of trust',
                'god bless', 'god-fearing', 'dying of cancer', 'terminal illness',
                'years to live', 'dying wish', 'orphaned funds', 'unclaimed funds',
                'foreign account', 'transfer the sum', 'sum of usd', 'sum of $',
            ]
            scam_hits = [s for s in scam_419 if s in content]
            if scam_hits:
                add_score(min(len(scam_hits) * 18, 54))
                indicators.append({'type': 'danger', 'title': f'Advance Fee / 419 Fraud ({len(scam_hits)} signal{"s" if len(scam_hits)>1 else ""})',
                                    'desc': f'Classic advance fee fraud language: "{scam_hits[0]}"'})
                danger_sections.add('content')

            crypto_keywords = [
                'send bitcoin', 'send btc', 'send crypto', 'pay in bitcoin', 'pay with bitcoin',
                'bitcoin payment', 'btc payment', 'ethereum payment', 'crypto payment',
                'cryptocurrency payment', 'wallet address', 'crypto wallet', 'bitcoin wallet',
                'gift card payment', 'itunes gift card', 'google play gift card',
                'amazon gift card', 'pay with gift card', 'pay in gift cards',
                'steam wallet code', 'buy gift cards', 'purchase gift cards',
            ]
            crypto_hits = [c for c in crypto_keywords if c in content]
            if crypto_hits:
                add_score(min(len(crypto_hits) * 18, 54))
                indicators.append({'type': 'danger', 'title': 'Untraceable Payment Demanded',
                                    'desc': f'Demands crypto or gift cards: "{crypto_hits[0]}" — 100% scam indicator'})
                danger_sections.add('content')

            sextortion = [
                'i have your password', 'i recorded you', 'i have footage of you',
                'your webcam', 'recorded via your webcam', 'watching you', 'hacked your device',
                'malware on your device', 'rat installed', 'remote access',
                'pay or i will', 'bitcoin or i will', 'send bitcoin or i',
                'embarrassing video', 'intimate video', 'explicit video',
                'sent to your contacts', 'sent to your friends', 'sent to your family',
            ]
            sext_hits = [s for s in sextortion if s in content]
            if sext_hits:
                add_score(50)
                indicators.append({'type': 'danger', 'title': 'Sextortion / Blackmail Attempt',
                                    'desc': 'This is a known scam format — do not pay, do not respond'})
                danger_sections.add('content')

            techsupport = [
                'your computer is infected', 'your pc is infected', 'your device is infected',
                'virus detected on your', 'malware detected', 'call microsoft', 'call apple support',
                'call our toll free', 'call our helpline', 'call our support',
                'technical support', 'tech support number', 'call 1-800', 'call +1-800',
                'toll free number', 'helpdesk number', 'support number',
                'do not restart your computer', 'do not shut down',
            ]
            tech_hits = [t for t in techsupport if t in content]
            if tech_hits:
                add_score(40)
                indicators.append({'type': 'danger', 'title': 'Tech Support Scam',
                                    'desc': f'Fake support alert: "{tech_hits[0]}" — do not call any number provided'})
                danger_sections.add('content')

            login_lure = [
                'click here to verify', 'click here to confirm', 'click the link to verify',
                'click the button below', 'click below to', 'tap to verify',
                'sign in to verify', 'log in to verify', 'login to confirm',
                'verify your account here', 'confirm your account here',
                'secure your account now', 'protect your account',
                'we detected unusual', 'we noticed unusual', 'we have detected',
                'your account has been', 'your account was accessed',
            ]
            login_hits = [l for l in login_lure if l in content]
            if login_hits:
                add_score(min(len(login_hits) * 14, 42))
                indicators.append({'type': 'danger', 'title': 'Account Takeover Lure',
                                    'desc': f'Directs user to click and log in: "{login_hits[0]}"'})
                danger_sections.add('content')

            gov_impersonation = [
                'internal revenue service', 'irs notice', 'tax authority', 'fbi notice',
                'cia notice', 'homeland security', 'department of justice',
                'court order', 'legal action will be taken', 'warrant has been issued',
                'arrest warrant', 'you are being investigated', 'criminal charges',
                'police department', 'interpol', 'customs and border',
                'social security administration', 'medicare', 'government benefit',
            ]
            gov_hits = [g for g in gov_impersonation if g in content]
            if gov_hits:
                add_score(min(len(gov_hits) * 16, 48))
                indicators.append({'type': 'danger', 'title': 'Government / Authority Impersonation',
                                    'desc': f'Impersonates official body: "{gov_hits[0]}" — government agencies do not cold-email threats'})
                danger_sections.add('content')

            generic_greet = ['dear customer', 'dear user', 'dear account holder', 'dear member',
                             'dear sir', 'dear madam', 'dear sir/madam', 'to whom it may concern',
                             'dear email owner', 'dear friend', 'hello friend']
            if any(g in content[:300] for g in generic_greet):
                add_score(8)
                indicators.append({'type': 'warning', 'title': 'Non-Personalized Generic Greeting',
                                    'desc': 'Legitimate services address you by name — generic greetings suggest mass phishing'})

        if urls_raw:
            url_list = [u.strip() for u in urls_raw.split(',') if u.strip()]
            seen_url_indicators = set()

            for url in url_list:
                url_lower = url.lower()

                matched_shortener = [s for s in SHORTENED_URL_SERVICES if s in url_lower]
                if matched_shortener and 'shortener' not in seen_url_indicators:
                    add_score(18)
                    indicators.append({'type': 'warning', 'title': 'URL Shortener Hides Destination',
                                        'desc': f'Real link concealed with shortener ({matched_shortener[0]}): {url[:80]}'})
                    seen_url_indicators.add('shortener')
                    danger_sections.add('url')

                if url_lower.startswith('http://') and 'http' not in seen_url_indicators:
                    add_score(15)
                    indicators.append({'type': 'danger', 'title': 'Unencrypted HTTP Link',
                                        'desc': f'Link uses plain HTTP — login forms over HTTP steal credentials in transit'})
                    seen_url_indicators.add('http')
                    danger_sections.add('url')

                if re.match(r'^https?://\d+\.\d+\.\d+\.\d+', url_lower) and 'ipurl' not in seen_url_indicators:
                    add_score(28)
                    indicators.append({'type': 'danger', 'title': 'Raw IP Address Used as URL',
                                        'desc': f'No legitimate company sends links to raw IP addresses'})
                    seen_url_indicators.add('ipurl')
                    danger_sections.add('url')

                for brand, legit_domain in IMPERSONATED_BRANDS.items():
                    legit_root = legit_domain.split('.')[0]
                    if legit_root in url_lower:
                        try:
                            parsed = urlparse(url_lower)
                            url_host = parsed.hostname or ''
                            if legit_domain not in url_host and f'{brand}-url-spoof' not in seen_url_indicators:
                                add_score(30)
                                indicators.append({'type': 'danger', 'title': f'URL Spoofs {brand.title()}',
                                                    'desc': f'URL contains "{legit_root}" but host is "{url_host}" — designed to look like {legit_domain}'})
                                seen_url_indicators.add(f'{brand}-url-spoof')
                                danger_sections.add('url')
                        except Exception:
                            pass
                        break

                pattern_hits = [p for p in SUSPICIOUS_URL_PATTERNS if p in url_lower]
                if pattern_hits and 'urlkw' not in seen_url_indicators:
                    add_score(12)
                    indicators.append({'type': 'warning', 'title': 'Suspicious URL Path Keywords',
                                        'desc': f'Path contains: {", ".join(pattern_hits[:4])}'})
                    seen_url_indicators.add('urlkw')
                    danger_sections.add('url')

                if any(ord(c) > 127 for c in url) and 'homograph' not in seen_url_indicators:
                    add_score(35)
                    indicators.append({'type': 'danger', 'title': 'Homograph / Unicode Spoofing Attack',
                                        'desc': 'URL contains non-ASCII characters designed to look like trusted domains'})
                    seen_url_indicators.add('homograph')
                    danger_sections.add('url')

                try:
                    parsed = urlparse(url_lower)
                    hostname = parsed.hostname or ''
                    if hostname.count('.') >= 3 and 'subdomain' not in seen_url_indicators:
                        add_score(18)
                        indicators.append({'type': 'danger', 'title': 'Suspicious Multi-Level Subdomain',
                                            'desc': f'"{hostname}" has {hostname.count(".")+1} domain levels — legitimate sites rarely use more than 2'})
                        seen_url_indicators.add('subdomain')
                        danger_sections.add('url')
                except Exception:
                    pass

                if sender_domain:
                    try:
                        parsed = urlparse(url_lower)
                        url_host = parsed.hostname or ''
                        url_root = '.'.join(url_host.split('.')[-2:]) if url_host else ''
                        sender_root = '.'.join(sender_domain.split('.')[-2:]) if sender_domain else ''
                        free_domains = {'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com'}
                        if url_root and sender_root and url_root != sender_root \
                                and sender_root not in free_domains \
                                and 'domain-mismatch' not in seen_url_indicators:
                            add_score(20)
                            indicators.append({'type': 'warning', 'title': 'URL Domain Mismatches Sender Domain',
                                                'desc': f'Sender is from "{sender_root}" but link points to "{url_root}" — possible redirect trick'})
                            seen_url_indicators.add('domain-mismatch')
                            danger_sections.add('url')
                    except Exception:
                        pass

                if (url_lower.startswith('data:') or url_lower.startswith('javascript:')) and 'dangeruri' not in seen_url_indicators:
                    add_score(40)
                    indicators.append({'type': 'danger', 'title': 'Dangerous URI Scheme (data:/javascript:)',
                                        'desc': 'This URI scheme can execute code directly in the browser'})
                    seen_url_indicators.add('dangeruri')
                    danger_sections.add('url')

                if len(url) > 200 and 'longurl' not in seen_url_indicators:
                    add_score(10)
                    indicators.append({'type': 'warning', 'title': 'Abnormally Long URL',
                                        'desc': f'URL is {len(url)} characters — excessive length often conceals the true destination'})
                    seen_url_indicators.add('longurl')

                if url_lower.count('%') > 5 and 'encoding' not in seen_url_indicators:
                    add_score(14)
                    indicators.append({'type': 'warning', 'title': 'Heavily Encoded URL',
                                        'desc': 'Excessive percent-encoding is used to hide malicious URL components'})
                    seen_url_indicators.add('encoding')
                    danger_sections.add('url')

        num_danger_sections = len(danger_sections)
        if num_danger_sections >= 4:
            add_score(30)
            indicators.append({'type': 'danger', 'title': 'All Sections Show Phishing Signals',
                                'desc': 'Subject, sender, body, AND URLs all contain independent risk indicators — high-confidence phishing'})
        elif num_danger_sections == 3:
            add_score(18)
            indicators.append({'type': 'danger', 'title': 'Multiple Independent Phishing Signals',
                                'desc': f'Risk detected across {num_danger_sections} separate email components — consistent with coordinated phishing'})
        elif num_danger_sections == 2:
            add_score(10)

        risk_score = min(100, max(0, risk_score))

        if not indicators:
            indicators.append({'type': 'safe', 'title': 'No Threats Detected',
                                'desc': 'Email passes all security checks — appears legitimate'})

        if risk_score < 20:
            recommendations.extend([
                '✓ This email appears legitimate.',
                '✓ Always verify the full sender address, not just the display name.',
                '✓ When in doubt, navigate to the company website directly rather than clicking links.',
            ])
        elif risk_score < 45:
            recommendations.extend([
                '⚠ This email has some suspicious characteristics — proceed with caution.',
                '⚠ Do not click links. Navigate to the site manually if needed.',
                '⚠ Do not download or open any attachments.',
                '⚠ Contact the supposed sender through official channels to verify.',
                '⚠ Report to your email provider as suspicious.',
            ])
        elif risk_score < 70:
            recommendations.extend([
                '🚨 Strong phishing indicators present — do not interact with this email.',
                '🚨 Do not click links, open attachments, or call any phone numbers listed.',
                '🚨 Do not provide any personal, financial, or login information.',
                '🚨 Mark as phishing and report to your email provider.',
                '🚨 If you already clicked a link, change your passwords immediately and enable 2FA.',
                '🚨 Monitor bank accounts and credit for suspicious activity.',
            ])
        else:
            recommendations.extend([
                '🚨 CRITICAL: This email is almost certainly a phishing or scam attack.',
                '🚨 Delete immediately. Do not open attachments or click any links.',
                '🚨 Do not call any phone numbers listed — they connect to scammers.',
                '🚨 Report to your IT security team, email provider, and national cybercrime agency.',
                '🚨 If you clicked anything or entered credentials: change all passwords now, enable 2FA, run antivirus.',
                '🚨 If money was transferred: contact your bank immediately — time is critical.',
                '🚨 Consider alerting colleagues if sent to a work account.',
            ])

        return jsonify({
            'success': True,
            'risk_score': risk_score,
            'indicators': indicators,
            'recommendations': recommendations
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/password/analyze', methods=['POST'])
def analyze_password():
    try:
        data = request.json
        password = data.get('password', '')

        if not password:
            return jsonify({'success': True, 'strength': 0, 'level': 'No Password', 'requirements': {}, 'tips': []})

        strength = 0
        requirements = {
            'length': len(password) >= 8,
            'length_long': len(password) >= 12,
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'numbers': bool(re.search(r'[0-9]', password)),
            'special': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`]', password)),
        }

        if requirements['length']: strength += 10
        if requirements['length_long']: strength += 15
        if requirements['uppercase']: strength += 15
        if requirements['lowercase']: strength += 15
        if requirements['numbers']: strength += 15
        if requirements['special']: strength += 25

        unique_chars = len(set(password))
        strength += min(5, unique_chars // 5)

        if re.search(r'(.)\1{2,}', password): strength -= 10
        if re.search(r'123|abc|qwerty|password|admin|letmein', password.lower()): strength -= 15

        common_words = ['password', 'admin', 'letmein', 'welcome', 'monkey', 'dragon', 'master', 'shadow']
        if any(word in password.lower() for word in common_words): strength -= 10

        strength = max(0, min(100, strength))

        if strength < 30: level = 'Weak'
        elif strength < 50: level = 'Fair'
        elif strength < 70: level = 'Good'
        elif strength < 90: level = 'Strong'
        else: level = 'Very Strong'

        tips = []
        if not requirements['length_long']: tips.append('Use at least 12 characters for enhanced security')
        if not requirements['uppercase']: tips.append('Add uppercase letters (A-Z)')
        if not requirements['lowercase']: tips.append('Add lowercase letters (a-z)')
        if not requirements['numbers']: tips.append('Include numbers (0-9)')
        if not requirements['special']: tips.append('Use special characters (!@#$%^&*)')
        if re.search(r'(.)\1{2,}', password): tips.append('Avoid repeating characters')
        if re.search(r'123|abc|qwerty', password.lower()): tips.append('Avoid common sequences (123, abc, qwerty)')
        if len(tips) == 0 and strength < 85: tips.append('Consider adding more special characters for extra security')

        diversity_score = min(100, (unique_chars / len(password)) * 100)
        length_score = min(100, (len(password) / 12) * 100)
        complexity_score = min(100, (strength / 1.2))

        return jsonify({
            'success': True,
            'strength': strength,
            'level': level,
            'requirements': requirements,
            'tips': tips,
            'metrics': {
                'diversity': round(diversity_score),
                'length': round(length_score),
                'complexity': round(complexity_score),
                'overall': strength
            }
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

def is_valid_profile_picture_url(picture_url):
    return picture_url and picture_url.startswith(('http://', 'https://')) and len(picture_url) < 2048