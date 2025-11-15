import math
import re
from typing import Dict
from collections import Counter

class FeatureExtractor:
    """Extract features from domain names for ML model"""
    
    SUSPICIOUS_TLDS = {
        '.tk': 5, '.ml': 5, '.ga': 5, '.cf': 5, '.gq': 5,
        '.xyz': 3, '.top': 3, '.win': 3, '.bid': 3,
        '.com': 1, '.net': 1, '.org': 1, '.edu': 0, '.gov': 0
    }
    
    SUSPICIOUS_KEYWORDS = [
        'login', 'secure', 'account', 'verify', 'update', 'confirm',
        'bank', 'paypal', 'ebay', 'amazon', 'apple', 'microsoft',
        'free', 'winner', 'prize', 'click', 'download'
    ]
    
    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        # Count character frequencies
        counter = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def get_tld_risk_score(domain: str) -> int:
        """Get risk score based on TLD"""
        for tld, score in FeatureExtractor.SUSPICIOUS_TLDS.items():
            if domain.endswith(tld):
                return score
        return 2  # Unknown TLD - medium risk
    
    @staticmethod
    def contains_suspicious_keywords(domain: str) -> bool:
        """Check if domain contains suspicious keywords"""
        domain_lower = domain.lower()
        return any(keyword in domain_lower for keyword in FeatureExtractor.SUSPICIOUS_KEYWORDS)
    
    @staticmethod
    def max_consonant_sequence(text: str) -> int:
        """Find maximum consecutive consonant sequence length"""
        vowels = set('aeiouAEIOU')
        max_len = 0
        current_len = 0
        
        for char in text:
            if char.isalpha() and char not in vowels:
                current_len += 1
                max_len = max(max_len, current_len)
            else:
                current_len = 0
        
        return max_len
    
    @staticmethod
    def extract_features(domain: str) -> Dict[str, float]:
        """
        Extract all features from a domain name
        
        Args:
            domain: Domain name to analyze
            
        Returns:
            Dictionary of features
        """
        # Remove protocol if present
        domain = domain.replace('http://', '').replace('https://', '')
        
        # Split into parts
        parts = domain.split('.')
        domain_name = parts[0] if parts else domain
        
        # Basic counts
        length = len(domain)
        digit_count = sum(c.isdigit() for c in domain)
        alpha_count = sum(c.isalpha() for c in domain)
        special_count = sum(not c.isalnum() and c != '.' for c in domain)
        vowel_count = sum(c.lower() in 'aeiou' for c in domain)
        consonant_count = sum(c.isalpha() and c.lower() not in 'aeiou' for c in domain)
        
        # Calculate ratios (avoid division by zero)
        digit_ratio = digit_count / length if length > 0 else 0
        special_ratio = special_count / length if length > 0 else 0
        vowel_ratio = vowel_count / length if length > 0 else 0
        consonant_ratio = consonant_count / length if length > 0 else 0
        
        # Extract features
        features = {
            # Length features
            'length': length,
            'domain_name_length': len(domain_name),
            'subdomain_count': len(parts) - 1,
            
            # Character composition
            'digit_ratio': digit_ratio,
            'special_char_ratio': special_ratio,
            'vowel_ratio': vowel_ratio,
            'consonant_ratio': consonant_ratio,
            'alpha_ratio': alpha_count / length if length > 0 else 0,
            
            # Entropy (randomness)
            'entropy': FeatureExtractor.calculate_entropy(domain_name),
            'full_entropy': FeatureExtractor.calculate_entropy(domain),
            
            # Pattern features
            'hyphen_count': domain.count('-'),
            'underscore_count': domain.count('_'),
            'dot_count': domain.count('.'),
            'max_consonant_sequence': FeatureExtractor.max_consonant_sequence(domain_name),
            
            # TLD risk
            'tld_risk_score': FeatureExtractor.get_tld_risk_score(domain),
            
            # Suspicious patterns
            'has_suspicious_keyword': int(FeatureExtractor.contains_suspicious_keywords(domain)),
            'has_ip_pattern': int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain))),
            'has_hex_pattern': int(bool(re.search(r'[0-9a-f]{8,}', domain.lower()))),
            
            # Statistical features
            'digit_alpha_ratio': digit_count / alpha_count if alpha_count > 0 else 0,
            'vowel_consonant_ratio': vowel_count / consonant_count if consonant_count > 0 else 0,
        }
        
        return features
    
    @staticmethod
    def get_feature_vector(domain: str) -> list:
        """
        Get feature vector as a list (for ML model prediction)
        
        Args:
            domain: Domain name
            
        Returns:
            List of feature values in consistent order
        """
        features = FeatureExtractor.extract_features(domain)
        
        # Return features in consistent order
        feature_order = [
            'length', 'domain_name_length', 'subdomain_count',
            'digit_ratio', 'special_char_ratio', 'vowel_ratio', 'consonant_ratio', 'alpha_ratio',
            'entropy', 'full_entropy',
            'hyphen_count', 'underscore_count', 'dot_count', 'max_consonant_sequence',
            'tld_risk_score',
            'has_suspicious_keyword', 'has_ip_pattern', 'has_hex_pattern',
            'digit_alpha_ratio', 'vowel_consonant_ratio'
        ]
        
        return [features[key] for key in feature_order]