from langchain.tools import tool

@tool("csv_reader")
def csv_reader(path: str) -> str:
    """Read and parse CSV files from the local filesystem."""
    import os
    if not os.path.exists(path):
        return f"File not found: {path}"
    with open(path, 'r') as f:
        return f.read()
