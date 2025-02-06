from flask import Flask, request, jsonify, render_template
import joblib
import numpy as np
import os
import json
import logging


app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


logging.basicConfig(level=logging.INFO)


MODEL_PATH = "models/ransomware_ensemble_model.pkl"
try:
    model = joblib.load(MODEL_PATH)
    logging.info("Model loaded successfully.")
except FileNotFoundError:
    model = None
    logging.error("Model file not found. Please ensure the model file exists at the specified path.")


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict_from_file():
    if not model:
        return jsonify({"error": "Model not loaded. Please check the model path."}), 500

    try:
       
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]

       
        if file.filename == "" or not file.filename.endswith(".json"):
            return jsonify({"error": "Uploaded file must be a JSON file"}), 400


        filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(filepath)

        with open(filepath, "r") as f:
            data = json.load(f)

        
        required_features = [
            "DebugSize", "DebugRVA", "MajorImageVersion", "MajorOSVersion",
            "ExportRVA", "ExportSize", "IatVRA", "MajorLinkerVersion",
            "MinorLinkerVersion", "NumberOfSections", "SizeOfStackReserve",
            "DllCharacteristics", "ResourceSize", "BitcoinAddresses"
        ]

   
        missing_features = [feature for feature in required_features if feature not in data]
        if missing_features:
            return jsonify({"error": f"Missing features: {', '.join(missing_features)}"}), 400

      
        features = np.array([[data[feature] for feature in required_features]]).astype(float)

   
        logging.info(f"Input features: {features}")

   
        prediction = model.predict(features)[0]
        prediction_prob = model.predict_proba(features)[0]

       
        logging.info(f"Prediction: {prediction}, Probabilities: {prediction_prob}")

      
        prediction_label = "No Ransomware Detected" if prediction == 1 else "Ransomware Detected"

    
        response = {
            "prediction": prediction_label,
          
            
        }

       
        os.remove(filepath)

        return jsonify(response), 200

    except Exception as e:
        logging.error(f"Error during prediction: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
