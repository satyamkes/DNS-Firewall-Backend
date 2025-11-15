import socket
import threading
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A
from dnslib.server import DNSServer, BaseResolver
import time
from typing import Tuple
from app.core.rule_engine import RuleEngine
from app.core.ml_model import get_ml_model
from app.config import settings
import logging

logger = logging.getLogger(__name__)

class SmartDNSResolver(BaseResolver):
    """Custom DNS resolver with ML-based filtering"""
    
    def __init__(self, firewall_engine):
        self.firewall_engine = firewall_engine
        self.upstream_dns = settings.UPSTREAM_DNS
        self.upstream_port = settings.UPSTREAM_DNS_PORT
        
        # Blocked response IP (NXDOMAIN or redirect)
        self.blocked_ip = "0.0.0.0"
        
        logger.info(f"DNS Resolver initialized with upstream {self.upstream_dns}:{self.upstream_port}")
    
    def resolve(self, request, handler):
        """
        Resolve DNS request with filtering
        
        Args:
            request: DNS request packet
            handler: Request handler
            
        Returns:
            DNS response
        """
        reply = request.reply()
        qname = str(request.q.qname).rstrip('.')
        qtype = QTYPE[request.q.qtype]
        
        logger.debug(f"DNS Query: {qname} ({qtype})")
        
        try:
            # Check domain through firewall
            start_time = time.time()
            decision, confidence, reason, source_ip = self.firewall_engine.check_domain(
                qname, 
                handler.client_address[0] if handler else "unknown"
            )
            processing_time = (time.time() - start_time) * 1000  # ms
            
            logger.info(f"Domain: {qname} | Decision: {decision} | Confidence: {confidence:.2f} | Time: {processing_time:.1f}ms")
            
            if decision == "BLOCK":
                # Return blocked response
                reply.add_answer(
                    RR(qname, QTYPE.A, rdata=A(self.blocked_ip), ttl=60)
                )
                logger.warning(f"BLOCKED: {qname} - {reason}")
            
            elif decision == "REVIEW":
                # For review, we can either:
                # 1. Block temporarily (safer)
                # 2. Allow but log for review
                # Here we'll allow but mark for review
                upstream_response = self._query_upstream(qname, qtype)
                if upstream_response:
                    reply = upstream_response
                logger.info(f"REVIEW: {qname} - {reason}")
            
            else:  # ALLOW
                # Query upstream DNS
                upstream_response = self._query_upstream(qname, qtype)
                if upstream_response:
                    reply = upstream_response
                logger.debug(f"ALLOWED: {qname}")
            
            return reply
            
        except Exception as e:
            logger.error(f"Error resolving {qname}: {e}")
            return reply
    
    def _query_upstream(self, domain: str, qtype: str) -> DNSRecord:
        """
        Query upstream DNS server
        
        Args:
            domain: Domain to resolve
            qtype: Query type (A, AAAA, etc.)
            
        Returns:
            DNS response record
        """
        try:
            # Create DNS query
            query = DNSRecord.question(domain, qtype)
            
            # Send to upstream DNS
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(query.pack(), (self.upstream_dns, self.upstream_port))
            
            # Receive response
            data, _ = sock.recvfrom(4096)
            sock.close()
            
            response = DNSRecord.parse(data)
            return response
            
        except Exception as e:
            logger.error(f"Error querying upstream DNS for {domain}: {e}")
            return None


class FirewallEngine:
    """Main firewall engine coordinating rule engine and ML model"""
    
    def __init__(self, db_session_maker):
        self.rule_engine = RuleEngine()
        self.ml_model = get_ml_model()
        self.db_session_maker = db_session_maker
        
        # Load whitelist and blacklist
        self._load_lists()
    
    def _load_lists(self):
        """Load whitelist and blacklist from database"""
        try:
            with self.db_session_maker() as db:
                from app.models.dns_log import Whitelist, Blacklist
                
                whitelist_domains = {w.domain for w in db.query(Whitelist).all()}
                blacklist_domains = {b.domain for b in db.query(Blacklist).all()}
                
                self.rule_engine.load_lists(whitelist_domains, blacklist_domains)
                logger.info(f"Loaded {len(whitelist_domains)} whitelist and {len(blacklist_domains)} blacklist domains")
        except Exception as e:
            logger.error(f"Error loading lists: {e}")
    
    def check_domain(self, domain: str, source_ip: str = "unknown") -> Tuple[str, float, str, str]:
        """
        Check domain through rule engine and ML model
        
        Args:
            domain: Domain to check
            source_ip: Source IP address
            
        Returns:
            Tuple of (decision, confidence, reason, source_ip)
        """
        start_time = time.time()
        
        # Step 1: Rule Engine (Fast heuristic check)
        rule_decision, rule_confidence, rule_reason = self.rule_engine.check_domain(domain)
        
        # If rule engine is certain, use its decision
        if rule_decision in ["ALLOW", "BLOCK"]:
            decision = rule_decision
            confidence = rule_confidence
            reason = f"Rule Engine: {rule_reason}"
            method = "rule_engine"
        
        else:  # UNCERTAIN - use ML model
            ml_decision, ml_confidence, ml_reason = self.ml_model.predict(domain)
            decision = ml_decision
            confidence = ml_confidence
            reason = f"ML Model: {ml_reason}"
            method = "ml_model"
        
        processing_time = (time.time() - start_time) * 1000
        
        # Log to database
        self._log_decision(
            domain, decision, confidence, reason, 
            source_ip, processing_time, method
        )
        
        return decision, confidence, reason, source_ip
    
    def _log_decision(
        self, domain: str, decision: str, confidence: float, 
        reason: str, source_ip: str, processing_time: float, method: str
    ):
        """Log decision to database and blockchain"""
        try:
            with self.db_session_maker() as db:
                from app.models.dns_log import DNSLog
                from app.core.blockchain_log import BlockchainLogger
                from app.ml.feature_extractor import FeatureExtractor
                
                # Extract features for storage
                extractor = FeatureExtractor()
                features = extractor.extract_features(domain)
                
                # Create DNS log entry
                log_entry = DNSLog(
                    domain=domain,
                    decision=decision,
                    confidence=confidence,
                    reason=reason,
                    source_ip=source_ip,
                    domain_length=features['length'],
                    entropy=features['entropy'],
                    digit_ratio=features['digit_ratio'],
                    special_char_count=int(features['special_char_ratio'] * features['length']),
                    tld_risk_score=features['tld_risk_score'],
                    rule_engine_result=method,
                    ml_model_used="RandomForest",
                    processing_time_ms=processing_time
                )
                
                db.add(log_entry)
                
                # Add to blockchain if enabled
                if settings.BLOCKCHAIN_ENABLED:
                    blockchain = BlockchainLogger(db)
                    blockchain.add_log(domain, decision, confidence, reason)
                
                db.commit()
                
        except Exception as e:
            logger.error(f"Error logging decision: {e}")


class DNSFirewallServer:
    """DNS Firewall Server"""
    
    def __init__(self, db_session_maker):
        self.firewall_engine = FirewallEngine(db_session_maker)
        self.resolver = SmartDNSResolver(self.firewall_engine)
        self.server = None
        self.thread = None
    
    def start(self):
        """Start the DNS server"""
        try:
            self.server = DNSServer(
                self.resolver,
                address=settings.DNS_BIND_ADDRESS,
                port=settings.DNS_BIND_PORT
            )
            
            logger.info(f"Starting DNS Firewall on {settings.DNS_BIND_ADDRESS}:{settings.DNS_BIND_PORT}")
            
            # Run in separate thread
            self.thread = threading.Thread(target=self.server.start, daemon=True)
            self.thread.start()
            
            logger.info("DNS Firewall started successfully")
            
        except Exception as e:
            logger.error(f"Error starting DNS server: {e}")
            raise
    
    def stop(self):
        """Stop the DNS server"""
        if self.server:
            self.server.stop()
            logger.info("DNS Firewall stopped")
    
    def reload_lists(self):
        """Reload whitelist and blacklist"""
        self.firewall_engine._load_lists()
        logger.info("Lists reloaded")