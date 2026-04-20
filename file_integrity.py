import hashlib
import os
import json

def hash_file(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def create_baseline(folder):
    baseline = {}
    for filename in os.listdir(folder):
        filepath = os.path.join(folder, filename)
        if os.path.isfile(filepath):
            baseline[filename] = hash_file(filepath)
    with open("baseline.json", "w") as f:
        json.dump(baseline, f, indent=4)
    print(f"Baseline created for {len(baseline)} file(s).")

def check_integrity(folder):
    with open("baseline.json", "r") as f:
        baseline = json.load(f)

    print("\n--- Integrity Check ---")
    for filename, original_hash in baseline.items():
        filepath = os.path.join(folder, filename)
        if not os.path.exists(filepath):
            print(f"[MISSING]  {filename}")
        else:
            current_hash = hash_file(filepath)
            if current_hash == original_hash:
                print(f"[OK]       {filename}")
            else:
                print(f"[MODIFIED] {filename}")

if __name__ == "__main__":
    print("1. Create baseline\n2. Check integrity")
    choice = input("Choose: ")
    folder = input("Enter folder path to monitor: ")

    if choice == "1":
        create_baseline(folder)
    elif choice == "2":
        check_integrity(folder)
    else:
        print("Invalid choice")
tampered
