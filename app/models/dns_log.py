from sqlalchemy import Column, Integer, String, Float, DateTime, Enum, Text
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import enum

Base = declarative_base()

class DecisionType(str, enum.Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"

class DNSLog(Base):
    __tablename__ = "dns_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    domain = Column(String(255), nullable=False, index=True)
    decision = Column(Enum(DecisionType), nullable=False, index=True)
    confidence = Column(Float, nullable=False)
    reason = Column(Text, nullable=True)
    source_ip = Column(String(45), nullable=True, index=True)
    device_name = Column(String(100), nullable=True)
    category = Column(String(50), nullable=True)
    
    # Feature values (for analysis)
    domain_length = Column(Integer)
    entropy = Column(Float)
    digit_ratio = Column(Float)
    special_char_count = Column(Integer)
    tld_risk_score = Column(Integer)
    
    # Processing info
    rule_engine_result = Column(String(20))
    ml_model_used = Column(String(50))
    processing_time_ms = Column(Float)
    
    def __repr__(self):
        return f"<DNSLog(domain='{self.domain}', decision='{self.decision}')>"

class BlockchainLog(Base):
    __tablename__ = "blockchain_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    block_index = Column(Integer, unique=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    domain = Column(String(255), nullable=False)
    decision = Column(String(20), nullable=False)
    confidence = Column(Float, nullable=False)
    previous_hash = Column(String(64), nullable=False)
    current_hash = Column(String(64), nullable=False, unique=True)
    data = Column(Text)  # JSON data
    
    def __repr__(self):
        return f"<BlockchainLog(index={self.block_index}, hash='{self.current_hash[:8]}...')>"

class Settings(Base):
    __tablename__ = "settings"
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False)
    value = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<Settings(key='{self.key}', value='{self.value}')>"

class Whitelist(Base):
    __tablename__ = "whitelist"
    
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    added_at = Column(DateTime, default=datetime.utcnow)
    added_by = Column(String(100))
    reason = Column(Text)
    
    def __repr__(self):
        return f"<Whitelist(domain='{self.domain}')>"

class Blacklist(Base):
    __tablename__ = "blacklist"
    
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    added_at = Column(DateTime, default=datetime.utcnow)
    added_by = Column(String(100))
    reason = Column(Text)
    threat_level = Column(String(20))  # Low, Medium, High, Critical
    
    def __repr__(self):
        return f"<Blacklist(domain='{self.domain}')>"