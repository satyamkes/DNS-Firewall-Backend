"""
ML Model Training Script for DNS Firewall

This script trains a Random Forest classifier to detect malicious domains.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib
import logging
from pathlib import Path

from app.ml.feature_extractor import FeatureExtractor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DomainClassifierTrainer:
    """Train ML model for domain classification"""
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.model = None
    
    def load_datasets(self, safe_domains_file: str, malicious_domains_file: str) -> pd.DataFrame:
        """
        Load and combine training datasets
        
        Args:
            safe_domains_file: Path to safe domains CSV/TXT
            malicious_domains_file: Path to malicious domains CSV/TXT
            
        Returns:
            DataFrame with domains and labels
        """
        logger.info("Loading datasets...")
        
        # Load safe domains
        try:
            safe_df = pd.read_csv(safe_domains_file, names=['domain'])
            safe_df['label'] = 0  # 0 = safe
            logger.info(f"Loaded {len(safe_df)} safe domains")
        except Exception as e:
            logger.error(f"Error loading safe domains: {e}")
            safe_df = pd.DataFrame()
        
        # Load malicious domains
        try:
            malicious_df = pd.read_csv(malicious_domains_file, names=['domain'])
            malicious_df['label'] = 1  # 1 = malicious
            logger.info(f"Loaded {len(malicious_df)} malicious domains")
        except Exception as e:
            logger.error(f"Error loading malicious domains: {e}")
            malicious_df = pd.DataFrame()
        
        # Combine datasets
        df = pd.concat([safe_df, malicious_df], ignore_index=True)
        
        # Remove duplicates and clean
        df = df.drop_duplicates(subset=['domain'])
        df = df.dropna()
        
        # Shuffle
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        logger.info(f"Total dataset size: {len(df)} domains")
        logger.info(f"Class distribution: {df['label'].value_counts().to_dict()}")
        
        return df
    
    def extract_features_bulk(self, domains: list) -> pd.DataFrame:
        """
        Extract features for multiple domains
        
        Args:
            domains: List of domain names
            
        Returns:
            DataFrame with extracted features
        """
        logger.info(f"Extracting features for {len(domains)} domains...")
        
        features_list = []
        for domain in domains:
            try:
                features = self.feature_extractor.extract_features(domain)
                features_list.append(features)
            except Exception as e:
                logger.warning(f"Error extracting features for {domain}: {e}")
                continue
        
        features_df = pd.DataFrame(features_list)
        logger.info(f"Features extracted: {features_df.shape}")
        
        return features_df
    
    def train_model(
        self, 
        X_train: pd.DataFrame, 
        y_train: pd.Series,
        **model_params
    ):
        """
        Train Random Forest classifier
        
        Args:
            X_train: Training features
            y_train: Training labels
            **model_params: Additional parameters for RandomForestClassifier
        """
        logger.info("Training Random Forest model...")
        
        # Default parameters
        params = {
            'n_estimators': 100,
            'max_depth': 20,
            'min_samples_split': 5,
            'min_samples_leaf': 2,
            'random_state': 42,
            'n_jobs': -1,
            'verbose': 1
        }
        params.update(model_params)
        
        self.model = RandomForestClassifier(**params)
        self.model.fit(X_train, y_train)
        
        logger.info("Model training completed")
    
    def evaluate_model(
        self, 
        X_test: pd.DataFrame, 
        y_test: pd.Series
    ) -> dict:
        """
        Evaluate model performance
        
        Args:
            X_test: Test features
            y_test: Test labels
            
        Returns:
            Dictionary with evaluation metrics
        """
        logger.info("Evaluating model...")
        
        # Predictions
        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)[:, 1]
        
        # Metrics
        report = classification_report(y_test, y_pred, output_dict=True)
        cm = confusion_matrix(y_test, y_pred)
        auc = roc_auc_score(y_test, y_pred_proba)
        
        metrics = {
            'accuracy': report['accuracy'],
            'precision': report['1']['precision'],
            'recall': report['1']['recall'],
            'f1_score': report['1']['f1-score'],
            'auc_roc': auc,
            'confusion_matrix': cm.tolist(),
            'false_positive_rate': cm[0][1] / (cm[0][0] + cm[0][1]) if (cm[0][0] + cm[0][1]) > 0 else 0,
            'false_negative_rate': cm[1][0] / (cm[1][0] + cm[1][1]) if (cm[1][0] + cm[1][1]) > 0 else 0
        }
        
        logger.info(f"Accuracy: {metrics['accuracy']:.4f}")
        logger.info(f"Precision: {metrics['precision']:.4f}")
        logger.info(f"Recall: {metrics['recall']:.4f}")
        logger.info(f"F1-Score: {metrics['f1_score']:.4f}")
        logger.info(f"AUC-ROC: {metrics['auc_roc']:.4f}")
        logger.info(f"False Positive Rate: {metrics['false_positive_rate']:.4f}")
        logger.info(f"False Negative Rate: {metrics['false_negative_rate']:.4f}")
        
        return metrics
    
    def get_feature_importance(self) -> dict:
        """Get feature importance from trained model"""
        if self.model is None:
            return {}
        
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
        
        importance_dict = {
            name: float(importance)
            for name, importance in zip(feature_names, importances)
        }
        
        # Sort by importance
        sorted_importance = dict(
            sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)
        )
        
        logger.info("\nTop 10 Most Important Features:")
        for i, (feature, importance) in enumerate(list(sorted_importance.items())[:10], 1):
            logger.info(f"{i}. {feature}: {importance:.4f}")
        
        return sorted_importance
    
    def save_model(self, filepath: str = './app/ml/model.pkl'):
        """Save trained model to file"""
        if self.model is None:
            logger.error("No model to save")
            return
        
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, filepath)
        logger.info(f"Model saved to {filepath}")
    
    def cross_validate(self, X: pd.DataFrame, y: pd.Series, cv: int = 5):
        """Perform cross-validation"""
        logger.info(f"Performing {cv}-fold cross-validation...")
        
        scores = cross_val_score(
            self.model, X, y, cv=cv, scoring='accuracy', n_jobs=-1
        )
        
        logger.info(f"Cross-validation scores: {scores}")
        logger.info(f"Mean CV accuracy: {scores.mean():.4f} (+/- {scores.std() * 2:.4f})")
        
        return scores


def main():
    """Main training pipeline"""
    
    # Initialize trainer
    trainer = DomainClassifierTrainer()
    
    # Load datasets (you need to provide these files)
    # You can download from:
    # - Safe: Alexa Top 1M, Tranco list
    # - Malicious: PhishTank, OpenPhish, MalwareDomainList
    
    safe_domains_file = './data/safe_domains.csv'
    malicious_domains_file = './data/malicious_domains.csv'
    
    df = trainer.load_datasets(safe_domains_file, malicious_domains_file)
    
    if df.empty:
        logger.error("No data loaded. Please provide domain datasets.")
        return
    
    # Extract features
    features_df = trainer.extract_features_bulk(df['domain'].tolist())
    
    if features_df.empty:
        logger.error("Feature extraction failed")
        return
    
    # Prepare data
    X = features_df
    y = df['label'][:len(features_df)]  # Match lengths
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    logger.info(f"Training set: {len(X_train)} samples")
    logger.info(f"Test set: {len(X_test)} samples")
    
    # Train model
    trainer.train_model(X_train, y_train)
    
    # Evaluate
    metrics = trainer.evaluate_model(X_test, y_test)
    
    # Feature importance
    importance = trainer.get_feature_importance()
    
    # Cross-validation
    trainer.cross_validate(X_train, y_train, cv=5)
    
    # Save model
    trainer.save_model()
    
    logger.info("\n=== Training Complete ===")
    logger.info(f"Model saved and ready for deployment")


if __name__ == "__main__":
    main()