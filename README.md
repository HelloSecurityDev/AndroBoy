# AndroBoy
Android vulnerability and security scanner via ADB

# AndroBoy - Android Security Scanner

AndroBoy is a Python script designed to perform security scans on Android devices. It checks for known vulnerabilities in installed packages using the National Vulnerability Database (NVD), searches for known malware paths, and checks for suspicious permissions in installed applications.

## Features

- **Vulnerability Check:** Uses NVD database to identify vulnerabilities in installed packages.
- **Malware Detection:** Searches for known malware paths on the device.
- **Permission Analysis:** Checks for suspicious permissions in installed applications.

## Requirements

- Python 3.x
- ADB (Android Debug Bridge) installed and configured
- Internet connection (for downloading NVD database)

## Installation and Setup

1. Clone the repository:
   ```
   git clone github.com/HelloSecDev/AndroBoy
   cd AndroBoy
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure `scanner_config.ini` with your preferences.

4. Run the script:
   ```
   python AndroBoy.py --nvd-url <nvd-url> --output-format <json/text>
   ```

## Configuration

The script can be configured using a `scanner_config.ini` file. Below are the configurable parameters with their default values:

- `NVD_URL`: URL to download the NVD database (default: `https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.zip`)
- `NVD_ZIP_FILE`: Name of the downloaded NVD zip file (default: `nvdcve-1.1-2023.json.zip`)
- `NVD_JSON_FILE`: Name of the extracted NVD JSON file (default: `nvdcve-1.1-2023.json`)
- `SUSPICIOUS_PERMISSIONS_FILE`: JSON file to store suspicious permissions (default: `suspicious_permissions.json`)
- `KNOWN_MALWARE_PATHS_FILE`: JSON file to store known malware paths (default: `known_malware_paths.json`)
- `LOG_FILE`: Log file to save the scan results (default: `security_scan_log.json`)

## Usage

### Command Line Arguments

- `--nvd-url`: URL to download the NVD database (default is configured in `scanner_config.ini`).
- `--output-format`: Output format for results (`json` or `text`, default is `json`).

Example:
```bash
python androboy.py --nvd-url https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.zip --output-format text
```

## Output

- Results are saved in `security_scan_log.json` (or `security_scan_log.txt` if `--output-format text` is used).

## Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
