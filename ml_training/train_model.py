"""
ML Model Training Script
Trains a classifier on URL features to detect malicious URLs
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import pickle
import os
import sys

# Add parent directory to path to import from backend
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
from app.models.url_features import extract_all_features


def extract_features_from_urls(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract features from URLs in dataset
    
    Args:
        df: DataFrame with 'url' and 'label' columns
    
    Returns:
        DataFrame with extracted features
    """
    print("🔧 Extracting features from URLs...")
    
    features_list = []
    
    for idx, row in df.iterrows():
        if idx % 100 == 0:
            print(f"   Processing {idx}/{len(df)}...")
        
        try:
            features = extract_all_features(row['url'])
            features['label'] = row['label']
            features_list.append(features)
        except Exception as e:
            print(f"   ⚠ Error processing URL {row['url']}: {e}")
    
    features_df = pd.DataFrame(features_list)
    print(f"✓ Extracted features for {len(features_df)} URLs")
    
    return features_df


def prepare_training_data(features_df: pd.DataFrame):
    """
    Prepare features for training
    
    Returns:
        X_train, X_test, y_train, y_test
    """
    print("\n🔧 Preparing training data...")
    
    # Drop non-numeric columns
    numeric_features = features_df.select_dtypes(include=[np.number])
    
    # Separate features and labels
    X = numeric_features.drop('label', axis=1)
    y = features_df['label']
    
    # Split into train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"✓ Training set: {len(X_train)} samples")
    print(f"✓ Test set: {len(X_test)} samples")
    
    return X_train, X_test, y_train, y_test


def train_model(X_train, y_train):
    """
    Train Random Forest classifier
    
    Returns:
        Trained model
    """
    print("\n🤖 Training Random Forest model...")
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    
    print("✓ Model training complete")
    
    return model


def evaluate_model(model, X_test, y_test):
    """
    Evaluate model performance
    """
    print("\n📊 Evaluating model performance...")
    
    y_pred = model.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print(f"\n{'='*50}")
    print(f"Model Performance Metrics")
    print(f"{'='*50}")
    print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1 Score:  {f1:.4f}")
    print(f"{'='*50}\n")
    
    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    print("Confusion Matrix:")
    print(f"                Predicted")
    print(f"              Benign  Malicious")
    print(f"Actual Benign    {cm[0][0]:4d}     {cm[0][1]:4d}")
    print(f"      Malicious  {cm[1][0]:4d}     {cm[1][1]:4d}\n")
    
    # Feature Importance
    feature_importance = pd.DataFrame({
        'feature': X_test.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("Top 10 Most Important Features:")
    print(feature_importance.head(10).to_string(index=False))
    print()
    
    return accuracy, precision, recall, f1


def save_model(model, output_path: str = "../backend/data/trained_model.pkl"):
    """
    Save trained model to file
    """
    print(f"\n💾 Saving model to {output_path}...")
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'wb') as f:
        pickle.dump(model, f)
    
    print("✓ Model saved successfully")


def main():
    """Main training pipeline"""
    print("=" * 60)
    print("ML Model Training Pipeline")
    print("=" * 60)
    
    # Load dataset
    dataset_path = "data/url_dataset.csv"
    
    if not os.path.exists(dataset_path):
        print(f"\n❌ Error: Dataset not found at {dataset_path}")
        print("Please run prepare_dataset.py first")
        return
    
    print(f"\n📂 Loading dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)
    print(f"✓ Loaded {len(df)} URLs")
    
    # Extract features
    features_df = extract_features_from_urls(df)
    
    # Prepare training data
    X_train, X_test, y_train, y_test = prepare_training_data(features_df)
    
    # Train model
    model = train_model(X_train, y_train)
    
    # Evaluate model
    evaluate_model(model, X_test, y_test)
    
    # Save model
    save_model(model)
    
    print("\n" + "=" * 60)
    print("✅ Training complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Start the backend server: cd backend && uvicorn app.main:app --reload")
    print("2. The model will be automatically loaded by the API")


if __name__ == "__main__":
    main()
