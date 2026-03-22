import os
from pathlib import Path

def main():
    root_dir = Path(r"c:\Users\prem\Network")
    output_file = root_dir / "all_project_code.txt"

    include_exts = {".py", ".js", ".jsx", ".css", ".md", ".json", ".html"}
    exclude_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".gemini", ".system_generated"}
    exclude_files = {"package-lock.json", "all.txt", "all_project_code.txt", "build_all_code.py"}

    print(f"Aggregating all code from {root_dir}")
    print(f"Outputting to {output_file}")
    
    files_processed = 0

    with open(output_file, "w", encoding="utf-8", errors="replace") as outfile:
        outfile.write("# NetVisor Complete Project Source Code\n")
        outfile.write("# This file contains all relevant codebase files concatenated together.\n\n")
        
        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Modify dirnames in-place to prune excluded directories
            dirnames[:] = [d for d in dirnames if d not in exclude_dirs and not d.startswith('.')]
            
            for file in filenames:
                ext = os.path.splitext(file)[1].lower()
                if ext in include_exts and file not in exclude_files:
                    filepath = os.path.join(dirpath, file)
                    rel_path = os.path.relpath(filepath, root_dir)
                    
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="replace") as infile:
                            content = infile.read()
                            
                        outfile.write(f"\n{'='*80}\n")
                        outfile.write(f"FILE: {rel_path}\n")
                        outfile.write(f"{'='*80}\n")
                        outfile.write(content)
                        outfile.write("\n")
                        files_processed += 1
                    except Exception as e:
                        print(f"Skipping {rel_path} due to error: {e}")

    print(f"Successfully processed {files_processed} files.")
    print("Aggregation complete.")

if __name__ == "__main__":
    main()
