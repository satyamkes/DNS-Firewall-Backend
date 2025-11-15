import hashlib
import json
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from sqlalchemy.orm import Session
from app.models.dns_log import BlockchainLog
import logging

logger = logging.getLogger(__name__)

class BlockchainLogger:
    """Blockchain-inspired tamper-proof logging system"""
    
    def __init__(self, db: Session):
        self.db = db
        self._ensure_genesis_block()
    
    def _ensure_genesis_block(self):
        """Create genesis block if it doesn't exist"""
        genesis = self.db.query(BlockchainLog).filter(
            BlockchainLog.block_index == 0
        ).first()
        
        if not genesis:
            genesis_data = {
                'domain': 'GENESIS_BLOCK',
                'decision': 'INIT',
                'confidence': 1.0,
                'timestamp': datetime.utcnow().isoformat(),
                'message': 'Genesis block for Smart DNS Firewall'
            }
            
            genesis_hash = self._calculate_hash({
                'index': 0,
                'timestamp': genesis_data['timestamp'],
                'data': genesis_data,
                'previous_hash': '0' * 64
            })
            
            genesis_block = BlockchainLog(
                block_index=0,
                timestamp=datetime.utcnow(),
                domain='GENESIS_BLOCK',
                decision='INIT',
                confidence=1.0,
                previous_hash='0' * 64,
                current_hash=genesis_hash,
                data=json.dumps(genesis_data)
            )
            
            self.db.add(genesis_block)
            self.db.commit()
            logger.info("Genesis block created")
    
    def _calculate_hash(self, block_data: dict) -> str:
        """
        Calculate SHA-256 hash of block data
        
        Args:
            block_data: Dictionary containing block information
            
        Returns:
            Hexadecimal hash string
        """
        # Create deterministic string from block data
        block_string = json.dumps({
            'index': block_data['index'],
            'timestamp': str(block_data['timestamp']),
            'data': block_data['data'],
            'previous_hash': block_data['previous_hash']
        }, sort_keys=True)
        
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def add_log(
        self, 
        domain: str, 
        decision: str, 
        confidence: float, 
        reason: str = None,
        additional_data: dict = None
    ) -> BlockchainLog:
        """
        Add a new log entry to the blockchain
        
        Args:
            domain: Domain name
            decision: ALLOW, BLOCK, or REVIEW
            confidence: Confidence score (0.0 to 1.0)
            reason: Explanation for the decision
            additional_data: Extra data to store
            
        Returns:
            Created BlockchainLog object
        """
        try:
            # Get the last block
            last_block = self.db.query(BlockchainLog).order_by(
                BlockchainLog.block_index.desc()
            ).first()
            
            if not last_block:
                self._ensure_genesis_block()
                last_block = self.db.query(BlockchainLog).filter(
                    BlockchainLog.block_index == 0
                ).first()
            
            new_index = last_block.block_index + 1
            timestamp = datetime.utcnow()
            
            # Prepare block data
            log_data = {
                'domain': domain,
                'decision': decision,
                'confidence': confidence,
                'reason': reason,
                'timestamp': timestamp.isoformat()
            }
            
            if additional_data:
                log_data.update(additional_data)
            
            # Calculate hash
            block_data = {
                'index': new_index,
                'timestamp': timestamp.isoformat(),
                'data': log_data,
                'previous_hash': last_block.current_hash
            }
            
            current_hash = self._calculate_hash(block_data)
            
            # Create new block
            new_block = BlockchainLog(
                block_index=new_index,
                timestamp=timestamp,
                domain=domain,
                decision=decision,
                confidence=confidence,
                previous_hash=last_block.current_hash,
                current_hash=current_hash,
                data=json.dumps(log_data)
            )
            
            self.db.add(new_block)
            self.db.commit()
            
            logger.debug(f"Added block {new_index} for domain {domain}")
            
            return new_block
            
        except Exception as e:
            logger.error(f"Error adding blockchain log: {e}")
            self.db.rollback()
            raise
    
    def verify_chain(self) -> Tuple[bool, Optional[str]]:
        """
        Verify the integrity of the entire blockchain
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            blocks = self.db.query(BlockchainLog).order_by(
                BlockchainLog.block_index
            ).all()
            
            if len(blocks) < 1:
                return False, "No blocks in chain"
            
            # Verify genesis block
            if blocks[0].block_index != 0:
                return False, "Genesis block missing"
            
            # Verify each block
            for i in range(1, len(blocks)):
                current_block = blocks[i]
                previous_block = blocks[i - 1]
                
                # Check if previous hash matches
                if current_block.previous_hash != previous_block.current_hash:
                    return False, f"Chain broken at block {current_block.block_index}"
                
                # Recalculate hash and verify
                block_data = {
                    'index': current_block.block_index,
                    'timestamp': current_block.timestamp.isoformat(),
                    'data': json.loads(current_block.data),
                    'previous_hash': current_block.previous_hash
                }
                
                calculated_hash = self._calculate_hash(block_data)
                
                if calculated_hash != current_block.current_hash:
                    return False, f"Block {current_block.block_index} has been tampered"
            
            logger.info("Blockchain verification successful")
            return True, "Blockchain is valid"
            
        except Exception as e:
            logger.error(f"Error verifying blockchain: {e}")
            return False, f"Verification error: {str(e)}"
    
    def get_chain_stats(self) -> dict:
        """Get statistics about the blockchain"""
        try:
            total_blocks = self.db.query(BlockchainLog).count()
            
            first_block = self.db.query(BlockchainLog).order_by(
                BlockchainLog.block_index
            ).first()
            
            last_block = self.db.query(BlockchainLog).order_by(
                BlockchainLog.block_index.desc()
            ).first()
            
            is_valid, message = self.verify_chain()
            
            return {
                'total_blocks': total_blocks,
                'first_block_time': first_block.timestamp if first_block else None,
                'last_block_time': last_block.timestamp if last_block else None,
                'is_valid': is_valid,
                'validation_message': message
            }
            
        except Exception as e:
            logger.error(f"Error getting chain stats: {e}")
            return {'error': str(e)}
    
    def get_recent_blocks(self, limit: int = 20) -> List[dict]:
        """Get recent blocks from the chain"""
        try:
            blocks = self.db.query(BlockchainLog).order_by(
                BlockchainLog.block_index.desc()
            ).limit(limit).all()
            
            return [
                {
                    'block_index': block.block_index,
                    'timestamp': block.timestamp.isoformat(),
                    'domain': block.domain,
                    'decision': block.decision,
                    'confidence': block.confidence,
                    'current_hash': block.current_hash,
                    'previous_hash': block.previous_hash,
                    'data': json.loads(block.data) if block.data else {}
                }
                for block in blocks
            ]
            
        except Exception as e:
            logger.error(f"Error getting recent blocks: {e}")
            return []