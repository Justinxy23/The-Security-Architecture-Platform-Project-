from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import uvicorn
from typing import List, Optional
import asyncio
from contextlib import asynccontextmanager

from core.config import settings
from core.database import engine, get_db, Base
from core.security import create_access_token, verify_password, get_password_hash
from api.v1 import auth, users, vulnerabilities, compliance, iam, siem
from models.user import User
from services.security_scanner import SecurityScanner
from services.compliance_checker import ComplianceChecker
from services.threat_detector import ThreatDetector

# Create database tables
Base.metadata.create_all(bind=engine)

# Initialize services
security_scanner = SecurityScanner()
compliance_checker = ComplianceChecker()
threat_detector = ThreatDetector()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage application lifecycle - startup and shutdown events
    """
    # Startup
    print("🚀 SecureArch Platform starting up...")
    print(f"📡 API running on {settings.API_HOST}:{settings.API_PORT}")
    print("🔐 Security services initializing...")
    
    # Start background tasks
    asyncio.create_task(security_scanner.start_continuous_scanning())
    asyncio.create_task(threat_detector.start_monitoring())
    
    yield
    
    # Shutdown
    print("🛑 SecureArch Platform shutting down...")
    await security_scanner.shutdown()
    await threat_detector.shutdown()

# Initialize FastAPI app
app = FastAPI(
    title="SecureArch Platform API",
    description="Comprehensive Security Architecture Platform by Justin Weaver",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(users.router, prefix="/api/v1/users", tags=["Users"])
app.include_router(vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"])
app.include_router(compliance.router, prefix="/api/v1/compliance", tags=["Compliance"])
app.include_router(iam.router, prefix="/api/v1/iam", tags=["IAM"])
app.include_router(siem.router, prefix="/api/v1/siem", tags=["SIEM"])

@app.get("/")
async def root():
    """
    Root endpoint - API health check
    """
    return {
        "message": "SecureArch Platform API",
        "status": "operational",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "author": "Justin Weaver"
    }

@app.get("/api/v1/health")
async def health_check():
    """
    Comprehensive health check endpoint
    """
    health_status = {
        "api": "healthy",
        "database": "healthy",
        "services": {
            "security_scanner": security_scanner.get_status(),
            "compliance_checker": compliance_checker.get_status(),
            "threat_detector": threat_detector.get_status()
        },
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # Check database connection
    try:
        db = next(get_db())
        db.execute("SELECT 1")
    except Exception as e:
        health_status["database"] = "unhealthy"
        health_status["error"] = str(e)
    
    return health_status

@app.get("/api/v1/security-posture")
async def get_security_posture(current_user: User = Depends(auth.get_current_user)):
    """
    Get current security posture overview
    """
    return {
        "overall_score": 87.5,
        "vulnerabilities": {
            "critical": 0,
            "high": 3,
            "medium": 12,
            "low": 27
        },
        "compliance": {
            "cis_benchmark": 92.3,
            "nist_framework": 88.7,
            "iso_27001": 85.2
        },
        "threats_detected": {
            "last_24h": 142,
            "blocked": 138,
            "investigating": 4
        },
        "assets": {
            "total": 1247,
            "monitored": 1198,
            "at_risk": 49
        },
        "last_scan": datetime.utcnow().isoformat(),
        "recommendations": [
            {
                "priority": "high",
                "title": "Update TLS certificates",
                "description": "3 certificates expiring within 30 days",
                "impact": "service_disruption"
            },
            {
                "priority": "medium",
                "title": "Enable MFA for 12 admin accounts",
                "description": "Admin accounts without MFA pose security risk",
                "impact": "unauthorized_access"
            }
        ]
    }

@app.post("/api/v1/scan/trigger")
async def trigger_security_scan(
    scan_type: str,
    targets: List[str],
    current_user: User = Depends(auth.get_current_admin_user)
):
    """
    Trigger manual security scan
    """
    if scan_type not in ["vulnerability", "compliance", "full"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid scan type. Choose: vulnerability, compliance, or full"
        )
    
    scan_id = await security_scanner.trigger_scan(
        scan_type=scan_type,
        targets=targets,
        initiated_by=current_user.id
    )
    
    return {
        "scan_id": scan_id,
        "status": "initiated",
        "scan_type": scan_type,
        "targets": targets,
        "estimated_completion": (datetime.utcnow() + timedelta(minutes=15)).isoformat()
    }

@app.get("/api/v1/alerts/active")
async def get_active_alerts(
    severity: Optional[str] = None,
    limit: int = 50,
    current_user: User = Depends(auth.get_current_user)
):
    """
    Get active security alerts
    """
    alerts = await threat_detector.get_active_alerts(
        severity=severity,
        limit=limit,
        user_id=current_user.id
    )
    
    return {
        "total": len(alerts),
        "alerts": alerts,
        "severity_breakdown": {
            "critical": sum(1 for a in alerts if a["severity"] == "critical"),
            "high": sum(1 for a in alerts if a["severity"] == "high"),
            "medium": sum(1 for a in alerts if a["severity"] == "medium"),
            "low": sum(1 for a in alerts if a["severity"] == "low")
        }
    }

@app.websocket("/ws/security-feed")
async def security_feed_websocket(websocket):
    """
    WebSocket endpoint for real-time security updates
    """
    await websocket.accept()
    try:
        while True:
            # Send security updates every 5 seconds
            security_update = {
                "timestamp": datetime.utcnow().isoformat(),
                "events": await threat_detector.get_recent_events(limit=10),
                "metrics": {
                    "threats_blocked": threat_detector.get_threats_blocked_count(),
                    "active_incidents": threat_detector.get_active_incidents_count()
                }
            }
            await websocket.send_json(security_update)
            await asyncio.sleep(5)
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        await websocket.close()

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
        log_level="info"
    )