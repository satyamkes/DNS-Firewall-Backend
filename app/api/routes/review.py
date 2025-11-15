from fastapi import APIRouter, Depends, Body
from sqlalchemy.orm import Session
from typing import List

from app.main import get_db
from app.models.dns_log import DNSLog, DecisionType, Whitelist, Blacklist

router = APIRouter()

@router.get("/queue")
async def get_review_queue(db: Session = Depends(get_db)):
    """Get domains pending manual review"""
    reviews = db.query(DNSLog).filter(
        DNSLog.decision == DecisionType.REVIEW
    ).order_by(DNSLog.timestamp.desc()).limit(50).all()
    
    return [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "domain": log.domain,
            "confidence": log.confidence,
            "reason": log.reason,
            "source_ip": log.source_ip
        }
        for log in reviews
    ]

@router.post("/approve/{log_id}")
async def approve_domain(log_id: int, db: Session = Depends(get_db)):
    """Approve a domain (add to whitelist)"""
    log = db.query(DNSLog).filter(DNSLog.id == log_id).first()
    
    if not log:
        return {"error": "Log not found"}
    
    # Add to whitelist
    whitelist_entry = Whitelist(
        domain=log.domain,
        added_by="manual_review",
        reason=f"Approved from review queue (confidence: {log.confidence})"
    )
    
    db.add(whitelist_entry)
    
    # Update log decision
    log.decision = DecisionType.ALLOW
    log.reason = "Manually approved"
    
    db.commit()
    
    return {"message": f"Domain {log.domain} added to whitelist"}

@router.post("/block/{log_id}")
async def block_domain(log_id: int, threat_level: str = "Medium", db: Session = Depends(get_db)):
    """Block a domain (add to blacklist)"""
    log = db.query(DNSLog).filter(DNSLog.id == log_id).first()
    
    if not log:
        return {"error": "Log not found"}
    
    # Add to blacklist
    blacklist_entry = Blacklist(
        domain=log.domain,
        added_by="manual_review",
        reason=f"Blocked from review queue (confidence: {log.confidence})",
        threat_level=threat_level
    )
    
    db.add(blacklist_entry)
    
    # Update log decision
    log.decision = DecisionType.BLOCK
    log.reason = "Manually blocked"
    
    db.commit()
    
    return {"message": f"Domain {log.domain} added to blacklist"}
