# app.py
from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return 'Welcome to the Simple Website on Port 9999!'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9999)
