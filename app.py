from flask import Flask, render_template, request, jsonify
import json
import os
from services.log_analyzer import analyze_log_content

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max

# Load commands data
def load_commands():
    with open('data/commands.json', 'r', encoding='utf-8') as f:
        return json.load(f)

@app.route('/')
def index():
    try:
        commands = load_commands()
        return render_template('cheatsheet.html', commands=commands)
    except Exception as e:
        return render_template('error.html', error=str(e)), 500

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Check file extension
        if not (file.filename.endswith('.log') or file.filename.endswith('.txt')):
            return jsonify({'error': 'Only .log and .txt files allowed'}), 400
        
        try:
            # Read file content
            content = file.read()
            
            # Try to decode as text
            try:
                text_content = content.decode('utf-8')
            except UnicodeDecodeError:
                text_content = content.decode('latin-1')
            
            # Analyze log
            findings = analyze_log_content(text_content)
            return jsonify({'findings': findings}), 200
        
        except Exception as e:
            return jsonify({'error': 'Error processing file: ' + str(e)}), 500
    
    return render_template('analyze.html')

@app.route('/analyze-text', methods=['POST'])
def analyze_text():
    try:
        # Accept both JSON and form submissions
        text = ''
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            text = payload.get('log_text', '') if isinstance(payload, dict) else ''
        else:
            text = request.form.get('log_text', '')

        if text is None:
            text = ''

        # Normalize line endings and trim excessive size early
        # Limit: 200,000 chars
        if len(text) == 0 or not text.strip():
            return jsonify({'error': 'Log text is empty. Please paste some log lines.'}), 400
        if len(text) > 200_000:
            return jsonify({'error': 'Text is too long (max 200,000 characters).'}), 400

        normalized = text.replace('\r\n', '\n').replace('\r', '\n')

        findings = analyze_log_content(normalized)
        return jsonify({'findings': findings}), 200

    except Exception as e:
        return jsonify({'error': 'Error processing text: ' + str(e)}), 500

@app.route('/api/commands')
def api_commands():
    try:
        commands = load_commands()
        return jsonify(commands)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large (max 5MB)'}), 413

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
