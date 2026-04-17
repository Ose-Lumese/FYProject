from flask import Flask, render_template, request, jsonify, session
import os

app = Flask(__name__)
app.secret_key = "sentri_secret"

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/loading')
def loading():
    return render_template('loading.html')


@app.route('/results')
def results():
    # GET DATA FROM SESSION
    data = session.get("results")

    if not data:
        # fallback (prevents crash)
        data = {
            "total_flows": 0,
            "malicious_count": 0,
            "threats": []
        }

    return render_template(
        "results.html",
        total_flows=data["total_flows"],
        malicious_count=data["malicious_count"],
        threats=data["threats"]
    )


@app.route('/analyze', methods=['POST'])
def analyze():
    file = request.files.get('file')

    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    os.makedirs("uploads", exist_ok=True)
    file_path = os.path.join("uploads", file.filename)
    file.save(file_path)

    # MOCK MODEL OUTPUT
    result = {
        "total_flows": 3,
        "malicious_count": 1,
        "threats": [
            {
                "type": "Port Scan",
                "severity": "HIGH",
                "source_ip": "192.168.1.10",
                "dest_ip": "10.0.0.5",
                "service": "HTTP",
                "timestamp": "2026-04-16 10:00",
                "recommendation": "Block suspicious scanning activity"
            }
        ]
    }

    # SAVE FOR RESULTS PAGE
    session["results"] = result

    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True)