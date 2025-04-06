
import json
import pandas as pd
import tempfile as tf
import os
from pathlib import Path
import glob

data_dir = Path("data") # Global var defining where data is saved

def save_to_csv(data, filename="android_security_bulletins.csv"):
    df = pd.DataFrame(data, columns=["CVE ID", "Severity", "Component", "Bulletin URL"])
    df.to_csv(filename, index=False, encoding="utf-8")
    print(f"Data saved to {filename}")

def save_to_json(data, filename=None):
    data_dir.mkdir(parents=True, exist_ok=True)
    
    if filename is None:
        # Generate a temporary filename (only the basename)
        temp_file = tf.NamedTemporaryFile(delete=False, suffix=".json")
        filename = Path(temp_file.name).name
        temp_file.close()
    
    filepath = data_dir / filename
    with filepath.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def read_json_file(filename):
    filepath = data_dir / filename
    if not filepath.exists():
        raise FileNotFoundError(f"{filepath} does not exist.")
    with filepath.open("r", encoding="utf-8") as file:
        data = json.load(file)
    return data

def choose_json_file(text):
    data_dir = Path("data")
    json_files = list(data_dir.glob("*.json"))
    
    if not json_files:
        print("No JSON files found.")
        return None

    print("--" * 40)
    print("\n" + text + "\n")
    # Display the JSON files using only their file names
    for i, file in enumerate(json_files, start=1):
        print(f"{i}. {file.name}")
    print(f"{len(json_files)+1}. Exit\n")
    
    while True:
        try:
            choice = int(input(f"Option (1-{len(json_files)+1}): "))
            print("--" * 40)
            if 1 <= choice <= len(json_files):
                chosen_file = json_files[choice - 1]
                print(f"You have selected: {chosen_file.name}")
                return chosen_file.name
            elif choice == len(json_files) + 1:
                return False
            else:
                print("Invalid choice. Please choose a valid number from the list.")
        except ValueError:
            print("Please enter a valid number.")
        except Exception as e:
            print("FileHandler Error: ", e)