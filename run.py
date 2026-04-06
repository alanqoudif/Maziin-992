import sys
from app import create_app

app = create_app()

if __name__ == "__main__":
    port = 5000
    if "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])
    app.run(debug=True, port=port)
