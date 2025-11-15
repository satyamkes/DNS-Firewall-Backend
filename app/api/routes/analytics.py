from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta

from app.main import get_db
from app.models.dns_log import DNSLog, DecisionType

router = APIRouter()

@router.get("/confidence-distribution")
async def get_confidence_distribution(db: Session = Depends(get_db)):
    """Get ML model confidence distribution"""
    ranges = [
        (0.0, 0.2, "0-20%"),
        (0.2, 0.4, "20-40%"),
        (0.4, 0.6, "40-60%"),
        (0.6, 0.8, "60-80%"),
        (0.8, 1.0, "80-100%")
    ]
    
    distribution = []
    for min_conf, max_conf, label in ranges:
        count = db.query(func.count(DNSLog.id)).filter(
            DNSLog.confidence >= min_conf,
            DNSLog.confidence < max_conf
        ).scalar()
        
        distribution.append({
            "range": label,
            "count": count
        })
    
    return distribution

@router.get("/timeline")
async def get_timeline(hours: int = 24, db: Session = Depends(get_db)):
    """Get request timeline for the last N hours"""
    from sqlalchemy import extract
    
    start_time = datetime.utcnow() - timedelta(hours=hours)
    
    # Group by hour
    results = db.query(
        extract('hour', DNSLog.timestamp).label('hour'),
        DNSLog.decision,
        func.count(DNSLog.id).label('count')
    ).filter(
        DNSLog.timestamp >= start_time
    ).group_by('hour', DNSLog.decision).all()
    
    # Format data
    timeline = {}
    for hour, decision, count in results:
        hour_str = f"{int(hour):02d}:00"
        if hour_str not in timeline:
            timeline[hour_str] = {"allowed": 0, "blocked": 0, "review": 0}
        
        timeline[hour_str][decision.value.lower()] = count
    
    return [
        {"time": time, **data}
        for time, data in sorted(timeline.items())
    ]

@router.get("/devices")
async def get_device_analytics(db: Session = Depends(get_db)):
    """Get per-device analytics"""
    results = db.query(
        DNSLog.source_ip,
        DNSLog.device_name,
        func.count(DNSLog.id).label('total_requests'),
        func.sum(
            func.case([(DNSLog.decision == DecisionType.BLOCK, 1)], else_=0)
        ).label('blocked_requests')
    ).group_by(DNSLog.source_ip, DNSLog.device_name).all()
    
    return [
        {
            "ip": result.source_ip or "unknown",
            "device_name": result.device_name or "Unknown Device",
            "total_requests": result.total_requests,
            "blocked_requests": result.blocked_requests,
            "block_rate": (result.blocked_requests / result.total_requests * 100) 
                          if result.total_requests > 0 else 0
        }
        for result in results
    ]

@router.get("/top-blocked")
async def get_top_blocked_domains(limit: int = 10, db: Session = Depends(get_db)):
    """Get most frequently blocked domains"""
    results = db.query(
        DNSLog.domain,
        func.count(DNSLog.id).label('count')
    ).filter(
        DNSLog.decision == DecisionType.BLOCK
    ).group_by(DNSLog.domain).order_by(
        func.count(DNSLog.id).desc()
    ).limit(limit).all()
    
    return [
        {"domain": domain, "count": count}
        for domain, count in results
    ]

@router.get("/performance")
async def get_performance_metrics(db: Session = Depends(get_db)):
    """Get system performance metrics"""
    avg_time = db.query(func.avg(DNSLog.processing_time_ms)).scalar() or 0
    max_time = db.query(func.max(DNSLog.processing_time_ms)).scalar() or 0
    min_time = db.query(func.min(DNSLog.processing_time_ms)).scalar() or 0
    
    return {
        "average_processing_time_ms": round(avg_time, 2),
        "max_processing_time_ms": round(max_time, 2),
        "min_processing_time_ms": round(min_time, 2)
    }
