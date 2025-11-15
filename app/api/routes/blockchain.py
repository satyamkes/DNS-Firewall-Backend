from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.main import get_db
from app.core.blockchain_log import BlockchainLogger

router = APIRouter()

@router.get("/")
async def get_blockchain(limit: int = 20, db: Session = Depends(get_db)):
    """Get recent blocks from blockchain"""
    blockchain = BlockchainLogger(db)
    blocks = blockchain.get_recent_blocks(limit)
    return blocks

@router.get("/verify")
async def verify_blockchain(db: Session = Depends(get_db)):
    """Verify blockchain integrity"""
    blockchain = BlockchainLogger(db)
    is_valid, message = blockchain.verify_chain()
    
    return {
        "is_valid": is_valid,
        "message": message
    }

@router.get("/stats")
async def get_blockchain_stats(db: Session = Depends(get_db)):
    """Get blockchain statistics"""
    blockchain = BlockchainLogger(db)
    stats = blockchain.get_chain_stats()
    return stats


# ============================================
# app/api/routes/settings.py
# ============================================
from fastapi import APIRouter, Depends, Body
from sqlalchemy.orm import Session
from typing import List

from app.main import get_db
from app.models.dns_log import Whitelist, Blacklist, Settings as SettingsModel

router = APIRouter()

# Whitelist Management
@router.get("/whitelist")
async def get_whitelist(db: Session = Depends(get_db)):
    """Get all whitelisted domains"""
    whitelist = db.query(Whitelist).order_by(Whitelist.added_at.desc()).all()
    
    return [
        {
            "id": entry.id,
            "domain": entry.domain,
            "added_at": entry.added_at.isoformat(),
            "added_by": entry.added_by,
            "reason": entry.reason
        }
        for entry in whitelist
    ]

@router.post("/whitelist")
async def add_to_whitelist(
    domain: str = Body(..., embed=True),
    reason: str = Body(None, embed=True),
    db: Session = Depends(get_db)
):
    """Add domain to whitelist"""
    existing = db.query(Whitelist).filter(Whitelist.domain == domain).first()
    
    if existing:
        return {"error": "Domain already in whitelist"}
    
    entry = Whitelist(
        domain=domain,
        added_by="admin",
        reason=reason or "Manually added"
    )
    
    db.add(entry)
    db.commit()
    
    return {"message": f"Domain {domain} added to whitelist"}

@router.delete("/whitelist/{domain}")
async def remove_from_whitelist(domain: str, db: Session = Depends(get_db)):
    """Remove domain from whitelist"""
    entry = db.query(Whitelist).filter(Whitelist.domain == domain).first()
    
    if not entry:
        return {"error": "Domain not found in whitelist"}
    
    db.delete(entry)
    db.commit()
    
    return {"message": f"Domain {domain} removed from whitelist"}

# Blacklist Management
@router.get("/blacklist")
async def get_blacklist(db: Session = Depends(get_db)):
    """Get all blacklisted domains"""
    blacklist = db.query(Blacklist).order_by(Blacklist.added_at.desc()).all()
    
    return [
        {
            "id": entry.id,
            "domain": entry.domain,
            "added_at": entry.added_at.isoformat(),
            "added_by": entry.added_by,
            "reason": entry.reason,
            "threat_level": entry.threat_level
        }
        for entry in blacklist
    ]

@router.post("/blacklist")
async def add_to_blacklist(
    domain: str = Body(..., embed=True),
    reason: str = Body(None, embed=True),
    threat_level: str = Body("Medium", embed=True),
    db: Session = Depends(get_db)
):
    """Add domain to blacklist"""
    existing = db.query(Blacklist).filter(Blacklist.domain == domain).first()
    
    if existing:
        return {"error": "Domain already in blacklist"}
    
    entry = Blacklist(
        domain=domain,
        added_by="admin",
        reason=reason or "Manually added",
        threat_level=threat_level
    )
    
    db.add(entry)
    db.commit()
    
    return {"message": f"Domain {domain} added to blacklist"}

@router.delete("/blacklist/{domain}")
async def remove_from_blacklist(domain: str, db: Session = Depends(get_db)):
    """Remove domain from blacklist"""
    entry = db.query(Blacklist).filter(Blacklist.domain == domain).first()
    
    if not entry:
        return {"error": "Domain not found in blacklist"}
    
    db.delete(entry)
    db.commit()
    
    return {"message": f"Domain {domain} removed from blacklist"}

# Application Settings
@router.get("/")
async def get_settings(db: Session = Depends(get_db)):
    """Get all application settings"""
    settings = db.query(SettingsModel).all()
    
    return {
        setting.key: setting.value
        for setting in settings
    }

@router.put("/")
async def update_settings(
    settings: dict = Body(...),
    db: Session = Depends(get_db)
):
    """Update application settings"""
    for key, value in settings.items():
        setting = db.query(SettingsModel).filter(SettingsModel.key == key).first()
        
        if setting:
            setting.value = str(value)
        else:
            setting = SettingsModel(key=key, value=str(value))
            db.add(setting)
    
    db.commit()
    
    return {"message": "Settings updated successfully"}
