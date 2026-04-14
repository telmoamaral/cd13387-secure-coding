from flask import Flask, request, jsonify

app = Flask(__name__)

# @app.route('/')
@app.route('/', methods=['POST'])

def hello_world():
    # username = request.args.get('username')
    # password = request.args.get('password')
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username and password:
        return jsonify({'message': f'Hello, {username}! You logged in successfully.'})
    return jsonify({'message': 'Hello, World!'})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
