
import json
import pandas as pd
import tempfile as tf
import os
from pathlib import Path
import glob
import requests
import time
import sys
import zipfile

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

# Ja precis, vi tänker samma då. Tänkte mer vad som kan vara rätt i stunden, så att man får en bra utgångspunkt för att kunna utvecklas, lära sig och på sikt utforska olika andra möjligheter, vilket är positivt att kunna göra på samma bolag 

def read_json_file(filename, data_dir=data_dir):
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


def print_progress(message):
    """
    Clears the current line using ANSI escape sequences and writes the new message.
    This should overwrite the previous line in most terminals.
    """
    # "\033[2K" clears the current line; "\r" returns carriage to beginning.
    sys.stdout.write("\r\033[2K" + message)
    sys.stdout.flush()


def download_and_unzip_into_folder(url, filename, zip_filename, data_folder=""):
    # Create data folder if it doesn't exist.
    if not os.path.exists(data_folder):
        os.makedirs(data_folder)

    # Build URL and file names based on year.
    #url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip"
    #zip_filename = os.path.join(data_folder, f"nvdcve-1.1-{year}.json.zip")
    #filename = os.path.join(data_folder, f"nvdcve-1.1-{year}.json")
    # Check if the JSON file already exists.
    if os.path.exists(filename):
        print_progress(f"File already exists. Skipping download.")
        # Pause briefly so that the message is visible before overwriting.
        time.sleep(0.5)
        return



    #print_progress(f"[{year}] Downloading: {url}")
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.RequestException as e:
        print_progress(f"Failed to download: {e}")
        time.sleep(0.5)
        return

    # Save the zip file.
    with open(zip_filename, "wb") as f:
        f.write(response.content)
    
    # Extract the zip file.
    try:
        with zipfile.ZipFile(zip_filename, "r") as zip_ref:
            zip_ref.extractall(data_folder)
        print_progress(f"Downloaded and extracted {filename} successfully.")
        time.sleep(0.5)
    except zipfile.BadZipFile as e:
        print_progress(f"Error unzipping file: {e}")
        time.sleep(0.5)
    finally:
        # Remove the zip file.
        if os.path.exists(zip_filename):
            os.remove(zip_filename)

def remove_file(filename):
    data_dir = Path("data")
    filepath = data_dir / filename
    if filepath.exists():
        os.remove(filepath)
        print(f"File {filename} removed.")
    else:
        print(f"File {filename} does not exist.")