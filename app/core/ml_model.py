import joblib
import numpy as np
from typing import Tuple, Optional
import os
from app.ml.feature_extractor import FeatureExtractor
from app.config import settings
import logging

logger = logging.getLogger(__name__)

class MLModel:
    """Machine Learning model for domain classification"""
    
    def __init__(self, model_path: str = None):
        self.model_path = model_path or settings.ML_MODEL_PATH
        self.model = None
        self.feature_extractor = FeatureExtractor()
        self.is_loaded = False
        
    def load_model(self):
        """Load the trained ML model"""
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                self.is_loaded = True
                logger.info(f"ML model loaded successfully from {self.model_path}")
            else:
                logger.warning(f"ML model not found at {self.model_path}. Using rule-based only.")
                self.is_loaded = False
        except Exception as e:
            logger.error(f"Error loading ML model: {e}")
            self.is_loaded = False
    
    def predict(self, domain: str) -> Tuple[str, float, str]:
        """
        Predict if domain is malicious
        
        Args:
            domain: Domain name to classify
            
        Returns:
            Tuple of (decision, confidence, reason)
        """
        if not self.is_loaded or self.model is None:
            return "UNCERTAIN", 0.5, "ML model not available"
        
        try:
            # Extract features
            feature_vector = self.feature_extractor.get_feature_vector(domain)
            features_array = np.array(feature_vector).reshape(1, -1)
            
            # Get prediction probability
            probabilities = self.model.predict_proba(features_array)[0]
            
            # probabilities[0] = safe, probabilities[1] = malicious
            malicious_probability = probabilities[1]
            safe_probability = probabilities[0]
            
            # Make decision based on thresholds
            if malicious_probability >= settings.ML_CONFIDENCE_THRESHOLD:
                decision = "BLOCK"
                confidence = malicious_probability
                reason = f"ML model detected malicious pattern (confidence: {malicious_probability:.2%})"
            
            elif safe_probability >= settings.ML_CONFIDENCE_THRESHOLD:
                decision = "ALLOW"
                confidence = safe_probability
                reason = f"ML model classified as safe (confidence: {safe_probability:.2%})"
            
            else:
                decision = "REVIEW"
                confidence = max(malicious_probability, safe_probability)
                reason = f"ML model uncertain (malicious: {malicious_probability:.2%}, safe: {safe_probability:.2%})"
            
            return decision, confidence, reason
            
        except Exception as e:
            logger.error(f"Error during ML prediction: {e}")
            return "UNCERTAIN", 0.5, f"Prediction error: {str(e)}"
    
    def get_feature_importance(self) -> dict:
        """Get feature importance from the model"""
        if not self.is_loaded or self.model is None:
            return {}
        
        try:
            if hasattr(self.model, 'feature_importances_'):
                feature_names = [
                    'length', 'domain_name_length', 'subdomain_count',
                    'digit_ratio', 'special_char_ratio', 'vowel_ratio', 'consonant_ratio', 'alpha_ratio',
                    'entropy', 'full_entropy',
                    'hyphen_count', 'underscore_count', 'dot_count', 'max_consonant_sequence',
                    'tld_risk_score',
                    'has_suspicious_keyword', 'has_ip_pattern', 'has_hex_pattern',
                    'digit_alpha_ratio', 'vowel_consonant_ratio'
                ]
                
                importances = self.model.feature_importances_
                
                # Create dictionary sorted by importance
                feature_importance = {
                    name: float(importance) 
                    for name, importance in zip(feature_names, importances)
                }
                
                # Sort by importance
                sorted_importance = dict(
                    sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
                )
                
                return sorted_importance
            
        except Exception as e:
            logger.error(f"Error getting feature importance: {e}")
        
        return {}
    
    def explain_prediction(self, domain: str) -> dict:
        """
        Explain why a domain was classified a certain way
        
        Returns:
            Dictionary with prediction details and top contributing features
        """
        if not self.is_loaded:
            return {"error": "Model not loaded"}
        
        try:
            # Get prediction
            decision, confidence, reason = self.predict(domain)
            
            # Get features
            features = self.feature_extractor.extract_features(domain)
            
            # Get feature importance
            importance = self.get_feature_importance()
            
            # Find top contributing features for this specific domain
            top_features = []
            for feature_name, importance_value in list(importance.items())[:5]:
                if feature_name in features:
                    top_features.append({
                        'feature': feature_name,
                        'value': features[feature_name],
                        'importance': importance_value
                    })
            
            return {
                'domain': domain,
                'decision': decision,
                'confidence': confidence,
                'reason': reason,
                'top_contributing_features': top_features,
                'all_features': features
            }
            
        except Exception as e:
            logger.error(f"Error explaining prediction: {e}")
            return {"error": str(e)}

# Global model instance
ml_model = MLModel()

def get_ml_model() -> MLModel:
    """Get the global ML model instance"""
    if not ml_model.is_loaded:
        ml_model.load_model()
    return ml_model