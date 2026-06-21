import os

def load_dotenv():
    """
    Loads environment variables from a .env file if it exists.
    Checks multiple possible locations:
    1. Current working directory
    2. One directory up from current working directory
    3. Root directory (relative to this file)
    """
    possible_paths = [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.getcwd(), "..", ".env"),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".env")),
    ]
    # Remove duplicate paths while preserving order
    seen = set()
    unique_paths = []
    for p in possible_paths:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)

    for dotenv_path in unique_paths:
        if os.path.exists(dotenv_path) and os.path.isfile(dotenv_path):
            try:
                with open(dotenv_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        # Ignore empty lines and comments
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            key, val = line.split("=", 1)
                            key = key.strip()
                            val = val.strip()
                            # Strip outer quotes if present
                            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                                val = val[1:-1]
                            if key and key not in os.environ:
                                os.environ[key] = val
                break  # Stop after loading the first found .env file
            except Exception:
                pass
