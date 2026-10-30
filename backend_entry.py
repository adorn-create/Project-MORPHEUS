import argparse

import uvicorn


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="morpheus-backend")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    uvicorn.run("morpheus.main:app", host=args.host, port=args.port)
