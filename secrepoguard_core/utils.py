import os
import sys

def is_binary_file(filepath: str, blocksize: int = 1024) -> bool:
    """
    Checks if a file is binary by looking for null bytes in the first block of data.
    """
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(blocksize)
            return b'\x00' in chunk
    except Exception:
        # If we cannot open/read, treat as binary or unreadable to be safe
        return True

def read_text_file(filepath: str, max_size_bytes: int = 1024 * 1024) -> str:
    """
    Safely reads a text file up to max_size_bytes. 
    Handles decoding using utf-8 with fallback to latin-1/errors-replace.
    Returns empty string if file is larger than max_size_bytes or if it is binary.
    """
    try:
        if os.path.getsize(filepath) > max_size_bytes:
            return ""
        
        if is_binary_file(filepath):
            return ""
            
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except Exception:
        return ""
