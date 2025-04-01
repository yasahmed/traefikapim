from flask import Flask, jsonify, request

# Create Flask application
app = Flask(__name__)


# Define a sample route
@app.route('/api/data', methods=['GET'])
def get_data():
    # Sample data to return as JSON

    request_data = request.get_json()

    return request_data

@app.route('/api/headers', methods=['GET'])
def get_headers():
    # Get all request headers
    headers = dict(request.headers)
    # Return headers as JSON
    return jsonify(headers)

@app.route('/api/lower', methods=['GET'])  # Added POST to handle JSON input
def get_data_lower():
    # Get JSON data from the request
    request_data = request.get_json()
    
    if request_data is None:
        return jsonify({"error": "No JSON data provided"}), 400
    
    # Function to recursively convert strings to uppercase
    def to_uppercase(data):
        if isinstance(data, str):
            return data.upper()
        elif isinstance(data, dict):
            return {key.upper(): to_uppercase(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [to_uppercase(item) for item in data]
        else:
            return data  # Leave numbers, booleans, etc., unchanged

    # Convert the request data to uppercase
    modified_data = to_uppercase(request_data)
    
    # Return the modified data as JSON
    return jsonify(modified_data)

# Health check route
@app.route('/', methods=['GET'])
def health_check():
    return jsonify({"status": "Server is running"})

# Run the server
if __name__ == '__main__':
    app.run(
        host='0.0.0.0',  # Listen on all interfaces
        port=9099,       # Run on port 5000
        debug=True       # Enable debug mode for development
    )
