"""
Flask Backend for Deep Learning IDS
Modern TensorFlow 2.x API - Latest Version
Real-time intrusion detection API
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import numpy as np
import pandas as pd
import pickle
import tensorflow as tf
import keras   # ✅ FIXED: Use Keras 3 directly instead of tf.keras
import os
import json
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# ============================================================================
# MODERN TENSORFLOW 2.x FOCAL LOSS (Latest API)
# ============================================================================

@keras.saving.register_keras_serializable()
class FocalLoss(keras.losses.Loss):
    """Modern Focal Loss implementation using TensorFlow 2.x"""
    
    def __init__(self, gamma=2.0, alpha=0.25, name='focal_loss'):
        super().__init__(name=name)
        self.gamma = gamma
        self.alpha = alpha
    
    def call(self, y_true, y_pred):
        epsilon = keras.backend.epsilon()
        y_pred = tf.clip_by_value(y_pred, epsilon, 1.0 - epsilon)
        
        # Calculate cross entropy
        cross_entropy = -y_true * tf.math.log(y_pred)
        
        # Calculate focal loss
        loss = self.alpha * tf.pow(1 - y_pred, self.gamma) * cross_entropy
        
        return tf.reduce_mean(tf.reduce_sum(loss, axis=-1))
    
    def get_config(self):
        config = super().get_config()
        config.update({
            'gamma': self.gamma,
            'alpha': self.alpha
        })
        return config

# ============================================================================
# MODERN IDS PREDICTOR CLASS
# ============================================================================

class IDSPredictor:
    def __init__(self):
        self.cnn_model = None
        self.lstm_model = None
        self.scaler = None
        self.label_encoder = None
        self.label_encoders = None
        self.feature_names = None
        self.cnn_thresholds = None
        self.lstm_thresholds = None
        self.num_features = None
        self.loaded = False
        
    def load_models(self):
        """Load trained models using modern TensorFlow 2.x API"""
        try:
            logger.info("Loading models with modern TensorFlow 2.x API...")
            
            # Custom objects for model loading
            custom_objects = {
                'FocalLoss': FocalLoss,
                'focal_loss': FocalLoss()
            }
            
            # Load models with modern API
            self.cnn_model = keras.models.load_model(
                'models/cnn_ids_model (1).h5',
                custom_objects=custom_objects,
                compile=False
            )
            
            self.lstm_model = keras.models.load_model(
                'models/lstm_ids_model (1).h5',
                custom_objects=custom_objects,
                compile=False
            )
            
            # Recompile with modern optimizer
            optimizer = keras.optimizers.Adam(learning_rate=0.001)
            
            self.cnn_model.compile(
                optimizer=optimizer,
                loss=FocalLoss(gamma=2.0, alpha=0.25),
                metrics=['accuracy']
            )
            
            self.lstm_model.compile(
                optimizer=optimizer,
                loss=FocalLoss(gamma=2.0, alpha=0.25),
                metrics=['accuracy']
            )
            
            # Load preprocessing artifacts
            with open('models/preprocessing_artifacts.pkl', 'rb') as f:
                artifacts = pickle.load(f)
            
            self.scaler = artifacts['scaler']
            self.label_encoder = artifacts['label_encoder']
            self.label_encoders = artifacts['label_encoders']
            self.feature_names = artifacts['feature_names']
            self.cnn_thresholds = artifacts['cnn_thresholds']
            self.lstm_thresholds = artifacts['lstm_thresholds']
            self.num_features = artifacts['num_features']
            
            self.loaded = True
            logger.info("✅ Models loaded successfully with TensorFlow 2.x")
            logger.info(f"TensorFlow version: {tf.__version__}")
            logger.info(f"Keras version: {keras.__version__}")
            logger.info(f"Classes: {self.label_encoder.classes_}")
            logger.info(f"GPU Available: {len(tf.config.list_physical_devices('GPU')) > 0}")
            
        except Exception as e:
            logger.error(f"❌ Error loading models: {str(e)}")
            logger.error("Make sure model files exist in /models")
            raise
    
    def preprocess_input(self, data):
        """Preprocess input data for prediction"""
        try:
            df = pd.DataFrame([data])
            
            # Feature engineering
            df['failed_login_ratio'] = df['num_failed_logins'] / (df['count'] + 1)
            df['guest_anomaly'] = df['is_guest_login'] * df['num_file_creations']
            df['service_error_pattern'] = df['srv_serror_rate'] * df['dst_host_srv_serror_rate']
            df['data_transfer_anomaly'] = df['src_bytes'] / (df['dst_bytes'] + 1)
            df['privilege_escalation_score'] = (df['su_attempted'] * 3 + 
                                                df['root_shell'] * 5 + 
                                                df['num_root'] * 2)
            df['root_access_pattern'] = df['root_shell'] * df['num_compromised']
            df['file_system_anomaly'] = (df['num_file_creations'] + 
                                         df['num_shells'] + 
                                         df['num_access_files'])
            
            # Encode categorical
            categorical_cols = ['protocol_type', 'service', 'flag']
            for col in categorical_cols:
                if col in df.columns and col in self.label_encoders:
                    try:
                        df[col] = self.label_encoders[col].transform(df[col].astype(str))
                    except:
                        df[col] = 0
            
            X = df[self.feature_names].values
            return self.scaler.transform(X)
            
        except Exception as e:
            logger.error(f"Error in preprocessing: {str(e)}")
            raise
    
    @tf.function
    def predict_batch(self, model, X):
        return model(X, training=False)
    
    def predict(self, data, use_ensemble=True):
        if not self.loaded:
            raise ValueError("Models not loaded. Call load_models() first.")
        
        X = self.preprocess_input(data)
        X_tensor = tf.convert_to_tensor(X, dtype=tf.float32)
        
        cnn_proba = self.predict_batch(self.cnn_model, X_tensor).numpy()[0]
        lstm_proba = self.predict_batch(self.lstm_model, X_tensor).numpy()[0]
        
        ensemble_proba = (cnn_proba + lstm_proba) / 2
        predicted_class = np.argmax(ensemble_proba)
        confidence = float(ensemble_proba[predicted_class])
        probabilities = ensemble_proba.tolist()
        
        attack_type = self.label_encoder.classes_[predicted_class]
        severity = self.get_severity(attack_type, confidence)
        threat_info = self.get_threat_info(attack_type)
        
        result = {
            'attack_type': attack_type,
            'confidence': confidence,
            'severity': severity,
            'model_used': "Ensemble (CNN + LSTM)",
            'probabilities': {
                self.label_encoder.classes_[i]: float(probabilities[i])
                for i in range(len(probabilities))
            },
            'threat_description': threat_info['description'],
            'recommendations': threat_info['recommendations'],
            'timestamp': datetime.now().isoformat(),
            'tensorflow_version': tf.__version__
        }
        
        return result
    
    @staticmethod
    def get_severity(attack_type, confidence):
        severity_map = {
            'Normal': 'Safe',
            'DoS': 'High',
            'Probe': 'Medium',
            'R2L': 'Critical',
            'U2R': 'Critical'
        }
        
        base = severity_map.get(attack_type, 'Unknown')
        
        if base in ['High', 'Critical'] and confidence < 0.6:
            return 'Medium'
        return base
    
    @staticmethod
    def get_threat_info(attack_type):
        threat_info = {
            'Normal': {
                'description': 'Normal network traffic detected.',
                'recommendations': [
                    'Maintain regular security monitoring',
                    'Keep firewalls updated'
                ]
            },
            'DoS': {
                'description': 'Denial of Service attack detected.',
                'recommendations': [
                    'Enable rate-limiting',
                    'Block suspicious IP addresses',
                    'Consider DDoS mitigation services'
                ]
            },
            'Probe': {
                'description': 'Network probing detected.',
                'recommendations': [
                    'Harden firewall rules',
                    'Monitor for follow-up attacks'
                ]
            },
            'R2L': {
                'description': 'Unauthorized remote access attempt detected.',
                'recommendations': [
                    'Change passwords immediately',
                    'Enable MFA'
                ]
            },
            'U2R': {
                'description': 'Privilege escalation detected.',
                'recommendations': [
                    'Isolate affected hosts',
                    'Perform full security audit'
                ]
            }
        }
        
        return threat_info.get(attack_type, {
            'description': 'Unknown threat type detected.',
            'recommendations': ['Investigate immediately']
        })

# Initialize predictor
predictor = IDSPredictor()

# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health', methods=['GET'])
def health_check():
    gpu_available = len(tf.config.list_physical_devices('GPU')) > 0
    
    return jsonify({
        'status': 'healthy',
        'models_loaded': predictor.loaded,
        'tensorflow_version': tf.__version__,
        'keras_version': keras.__version__,
        'gpu_available': gpu_available,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        
        required_fields = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes']
        missing = [field for field in required_fields if field not in data]
        
        if missing:
            return jsonify({'error': f'Missing fields: {", ".join(missing)}'}), 400
        
        result = predictor.predict(data, use_ensemble=True)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ✅ CSV UPLOAD ROUTE (Fix 404 error)
# ============================================================================

@app.route('/upload-csv', methods=['POST'])
def upload_csv():
    try:
        if 'file' not in request.files:
            return jsonify({'error':'No file uploaded'}), 400
        
        file = request.files['file']
        df = pd.read_csv(file)
        results = []
        
        for _, row in df.iterrows():
            try:
                results.append(predictor.predict(row.to_dict(), use_ensemble=True))
            except Exception as e:
                results.append({'error': str(e)})

        attack_counts = {}
        for r in results:
            if 'attack_type' in r:
                attack_counts[r['attack_type']] = attack_counts.get(r['attack_type'], 0) + 1

        return jsonify({
            'results': results,
            'summary': {
                'total_samples': len(results),
                'attack_distribution': attack_counts,
                'timestamp': datetime.now().isoformat()
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ✅ Alias if frontend calls /upload instead of /upload-csv
@app.route('/upload', methods=['POST'])
def upload_alias():
    return upload_csv()

# ============================================================================
# STARTUP
# ============================================================================

def initialize_app():
    logger.info("="*70)
    logger.info("Deep Learning IDS - TensorFlow + Keras 3 Backend")
    logger.info("="*70)
    os.makedirs('models', exist_ok=True)
    predictor.load_models()
    logger.info("✅ Application initialized successfully")

if __name__ == '__main__':
    initialize_app()
    app.run(debug=True, host='0.0.0.0', port=5001, threaded=True)
