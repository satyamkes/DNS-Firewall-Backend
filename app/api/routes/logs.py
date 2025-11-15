from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from app.main import get_db
from app.models.dns_log import DNSLog, DecisionType

router = APIRouter()

@router.get("/")
async def get_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    decision: Optional[str] = None,
    search: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: Session = Depends(get_db)
):
    """
    Get DNS logs with filtering and pagination
    
    Args:
        skip: Number of records to skip
        limit: Maximum number of records to return
        decision: Filter by decision type (ALLOW, BLOCK, REVIEW)
        search: Search in domain names
        start_date: Filter by start date
        end_date: Filter by end date
    """
    query = db.query(DNSLog)
    
    # Apply filters
    if decision:
        try:
            decision_enum = DecisionType[decision.upper()]
            query = query.filter(DNSLog.decision == decision_enum)
        except KeyError:
            pass
    
    if search:
        query = query.filter(DNSLog.domain.contains(search))
    
    if start_date:
        query = query.filter(DNSLog.timestamp >= start_date)
    
    if end_date:
        query = query.filter(DNSLog.timestamp <= end_date)
    
    # Get total count
    total = query.count()
    
    # Get paginated results
    logs = query.order_by(DNSLog.timestamp.desc()).offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "logs": [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat(),
                "domain": log.domain,
                "decision": log.decision.value,
                "confidence": log.confidence,
                "reason": log.reason,
                "source_ip": log.source_ip,
                "device_name": log.device_name,
                "category": log.category,
                "processing_time_ms": log.processing_time_ms
            }
            for log in logs
        ]
    }

@router.get("/{log_id}")
async def get_log_detail(log_id: int, db: Session = Depends(get_db)):
    """Get detailed information about a specific log entry"""
    log = db.query(DNSLog).filter(DNSLog.id == log_id).first()
    
    if not log:
        return {"error": "Log not found"}
    
    return {
        "id": log.id,
        "timestamp": log.timestamp.isoformat(),
        "domain": log.domain,
        "decision": log.decision.value,
        "confidence": log.confidence,
        "reason": log.reason,
        "source_ip": log.source_ip,
        "device_name": log.device_name,
        "category": log.category,
        "features": {
            "domain_length": log.domain_length,
            "entropy": log.entropy,
            "digit_ratio": log.digit_ratio,
            "special_char_count": log.special_char_count,
            "tld_risk_score": log.tld_risk_score
        },
        "processing": {
            "rule_engine_result": log.rule_engine_result,
            "ml_model_used": log.ml_model_used,
            "processing_time_ms": log.processing_time_ms
        }
    }

@router.get("/export/csv")
async def export_logs_csv(
    decision: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: Session = Depends(get_db)
):
    """Export logs as CSV"""
    from fastapi.responses import StreamingResponse
    import io
    import csv
    
    query = db.query(DNSLog)
    
    if decision:
        try:
            decision_enum = DecisionType[decision.upper()]
            query = query.filter(DNSLog.decision == decision_enum)
        except KeyError:
            pass
    
    if start_date:
        query = query.filter(DNSLog.timestamp >= start_date)
    
    if end_date:
        query = query.filter(DNSLog.timestamp <= end_date)
    
    logs = query.order_by(DNSLog.timestamp.desc()).all()
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'Timestamp', 'Domain', 'Decision', 'Confidence', 
        'Reason', 'Source IP', 'Processing Time (ms)'
    ])
    
    # Write data
    for log in logs:
        writer.writerow([
            log.timestamp.isoformat(),
            log.domain,
            log.decision.value,
            log.confidence,
            log.reason,
            log.source_ip,
            log.processing_time_ms
        ])
    
    output.seek(0)
    
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=dns_logs.csv"}
    )

@router.delete("/{log_id}")
async def delete_log(log_id: int, db: Session = Depends(get_db)):
    """Delete a specific log entry"""
    log = db.query(DNSLog).filter(DNSLog.id == log_id).first()
    
    if not log:
        return {"error": "Log not found"}
    
    db.delete(log)
    db.commit()
    
    return {"message": "Log deleted successfully"}

@router.delete("/")
async def clear_logs(
    older_than_days: int = Query(30, ge=1),
    db: Session = Depends(get_db)
):
    """Clear old logs"""
    cutoff_date = datetime.utcnow() - timedelta(days=older_than_days)
    
    deleted = db.query(DNSLog).filter(DNSLog.timestamp < cutoff_date).delete()
    db.commit()
    
    return {
        "message": f"Deleted {deleted} log entries older than {older_than_days} days"
    }