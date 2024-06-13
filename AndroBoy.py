import subprocess
import json
import os
import urllib.request
import zipfile
import threading
import logging
import argparse
import configparser

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Read configuration
config = configparser.ConfigParser()
config.read('scanner_config.ini')

DEFAULT_NVD_URL = config.get('DEFAULT', 'NVD_URL', fallback='https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.zip')
NVD_ZIP_FILE = config.get('DEFAULT', 'NVD_ZIP_FILE', fallback='nvdcve-1.1-2023.json.zip')
NVD_JSON_FILE = config.get('DEFAULT', 'NVD_JSON_FILE', fallback='nvdcve-1.1-2023.json')
SUSPICIOUS_PERMISSIONS_FILE = config.get('DEFAULT', 'SUSPICIOUS_PERMISSIONS_FILE', fallback='suspicious_permissions.json')
KNOWN_MALWARE_PATHS_FILE = config.get('DEFAULT', 'KNOWN_MALWARE_PATHS_FILE', fallback='known_malware_paths.json')
LOG_FILE = config.get('DEFAULT', 'LOG_FILE', fallback='security_scan_log.json')

DEFAULT_SUSPICIOUS_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.WRITE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.PROCESS_OUTGOING_CALLS"
]

DEFAULT_KNOWN_MALWARE_PATHS = [
    "/data/local/tmp/malware",
    "/sdcard/malicious.apk",
    "/data/data/com.example.malicious",
    "/data/data/com.android.systemupdate",
    "/data/data/com.example.hacktool"
]

def ensure_json_files():
    """Ensure JSON files for suspicious permissions and known malware paths are present and populated."""
    create_json_file_if_not_exists(SUSPICIOUS_PERMISSIONS_FILE, DEFAULT_SUSPICIOUS_PERMISSIONS)
    create_json_file_if_not_exists(KNOWN_MALWARE_PATHS_FILE, DEFAULT_KNOWN_MALWARE_PATHS)

def create_json_file_if_not_exists(file_path, default_data):
    """Create a JSON file with default data if it doesn't exist."""
    if not os.path.exists(file_path):
        logging.info(f"Creating {file_path}...")
        with open(file_path, 'w') as file:
            json.dump(default_data, file, indent=4)

def download_nvd_database(nvd_url, nvd_zip_file, nvd_json_file):
    """Download and unzip the NVD database if not present."""
    if not os.path.exists(nvd_json_file):
        logging.info("Downloading NVD database...")
        try:
            urllib.request.urlretrieve(nvd_url, nvd_zip_file)
            logging.info("Unzipping NVD database...")
            with zipfile.ZipFile(nvd_zip_file, 'r') as zip_ref:
                zip_ref.extractall()
            os.remove(nvd_zip_file)
            logging.info("NVD database downloaded and extracted.")
        except Exception as e:
            logging.error(f"Failed to download or unzip NVD database: {e}")

def adb_command(command):
    """Execute adb commands and return the output."""
    try:
        result = subprocess.run(["adb", "shell"] + command.split(), capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"ADB command failed: {e}")
        return ""

def get_installed_packages():
    """Get the list of installed packages on the device."""
    packages = adb_command("pm list packages").splitlines()
    return [pkg.replace("package:", "") for pkg in packages]

def check_vulnerabilities(packages, vulnerabilities):
    """Check for known vulnerabilities in installed packages using the NVD database."""
    try:
        with open(NVD_JSON_FILE, 'r') as file:
            nvd_data = json.load(file)
            for cve_item in nvd_data['CVE_Items']:
                description = cve_item['cve']['description']['description_data'][0]['value']
                for package in packages:
                    if package in description:
                        vulnerabilities.append(f"{package}: {cve_item['cve']['CVE_data_meta']['ID']} - {description}")
    except FileNotFoundError:
        logging.error(f"NVD JSON file not found: {NVD_JSON_FILE}")

def load_json_data(file_path):
    """Load JSON data from a file."""
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        logging.error(f"JSON file not found: {file_path}")
        return []
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from file: {file_path}")
        return []

def search_malware(malware_found):
    """Search for known malware files on the device."""
    known_malware_paths = load_json_data(KNOWN_MALWARE_PATHS_FILE)
    for path in known_malware_paths:
        if adb_command(f"ls {path}") != "":
            malware_found.append(path)

def check_permissions(suspicious_permissions):
    """Check for suspicious permissions in installed packages."""
    known_suspicious_permissions = load_json_data(SUSPICIOUS_PERMISSIONS_FILE)
    packages = get_installed_packages()
    for package in packages:
        permissions = adb_command(f"dumpsys package {package} | grep permission").splitlines()
        for permission in permissions:
            for suspicious_permission in known_suspicious_permissions:
                if suspicious_permission in permission:
                    suspicious_permissions.append(f"{package}: {suspicious_permission}")

def save_results(results, output_format):
    """Save the results to a log file in the specified format."""
    if output_format == 'json':
        with open(LOG_FILE, "w") as log_file:
            json.dump(results, log_file, indent=4)
    elif output_format == 'text':
        with open(LOG_FILE.replace('.json', '.txt'), "w") as log_file:
            for key, value in results.items():
                log_file.write(f"{key}:\n")
                for item in value:
                    log_file.write(f"  {item}\n")
                log_file.write("\n")
    logging.info(f"Security scan completed. Results saved to {LOG_FILE}")

def check_adb():
    """Check if adb is available."""
    if subprocess.run(["adb", "devices"], capture_output=True, text=True).returncode != 0:
        logging.error("ADB is not available. Please install ADB and enable USB debugging on your device.")
        return False
    return True

def main(nvd_url, output_format):
    """Main function to perform the security scan."""
    if not check_adb():
        return

    ensure_json_files()

    download_nvd_database(nvd_url, NVD_ZIP_FILE, NVD_JSON_FILE)

    device_info = {
        "model": adb_command("getprop ro.product.model"),
        "android_version": adb_command("getprop ro.build.version.release"),
        "sdk_version": adb_command("getprop ro.build.version.sdk")
    }

    packages = get_installed_packages()
    vulnerabilities = []
    malware_found = []
    suspicious_permissions = []

    threads = [
        threading.Thread(target=check_vulnerabilities, args=(packages, vulnerabilities)),
        threading.Thread(target=search_malware, args=(malware_found,)),
        threading.Thread(target=check_permissions, args=(suspicious_permissions,))
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    results = {
        "device_info": device_info,
        "vulnerabilities": vulnerabilities,
        "malware_found": malware_found,
        "suspicious_permissions": suspicious_permissions
    }

    save_results(results, output_format)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AndroBoy - Android security scanner - By Adam Rivers of Hello Security LLC")
    parser.add_argument("--nvd-url", type=str, default=DEFAULT_NVD_URL, help="URL to download the NVD database")
    parser.add_argument("--output-format", type=str, choices=['json', 'text'], default='json', help="Output format for the results")
    args = parser.parse_args()

    main(args.nvd_url, args.output_format)
