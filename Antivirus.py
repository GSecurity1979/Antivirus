import ctypes
import win32api
import win32con
import win32security
import win32process
import win32file
import logging
import logging.handlers
import subprocess
import os
import aiohttp
import asyncio
import shutil
from pathlib import Path
import psutil
import sys
import time
import numpy as np
import sounddevice as sd
from scipy.signal import butter, lfilter
from collections import deque
import threading
from psutil import AccessDenied, NoSuchProcess, ZombieProcess
from OpenSSL import crypto

# Configuration
VIRUSTOTAL_API_KEY = '28d53b2690cc5d8afc29c7e5104902742af02f14c80368ef4bbd2d01e57e1b77'
LOG_FILE = 'malware_detection.log'
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 5
BLOCKED_URLS_FILE = 'blocked_urls.txt'
SUSPICIOUS_APIS = ["SetWindowsHookExW", "CreateRemoteThread"]
OVERLAY_KEYWORDS = ["overlay", "hook", "dll"]

# Setup logging
logger = logging.getLogger('MalwareDetector')
logger.setLevel(logging.INFO)
handler = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=BACKUP_COUNT)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def run_as_admin():
    """Re-run the script as an administrator using UAC."""
    if ctypes.windll.shell32.IsUserAnAdmin():
        return
    else:
        try:
            params = ' '.join(sys.argv)
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            sys.exit()
        except Exception as e:
            logger.error(f"Error running as admin: {e}")
            sys.exit()

# Audio Processing Functions using sounddevice
def butter_bandpass(lowcut, highcut, fs, order=5):
    nyquist = 0.5 * fs
    low = lowcut / nyquist
    high = highcut / nyquist
    b, a = butter(order, [low, high], btype='band')
    return b, a

def bandpass_filter(data, lowcut, highcut, fs, order=5):
    b, a = butter_bandpass(lowcut, highcut, fs, order=order)
    y = lfilter(b, a, data)
    return y

delay_buffer = deque(maxlen=4410)

def audio_callback(indata, frames, time, status):
    fs = 44100
    lowcut = 20.0
    highcut = 20000.0
    filtered_data = bandpass_filter(indata[:, 0], lowcut, highcut, fs)
    delay_buffer.extend(filtered_data)
    if len(delay_buffer) >= frames:
        out_data = np.array([delay_buffer.popleft() for _ in range(frames)])
    else:
        out_data = np.zeros(frames, dtype=np.float32)
    return out_data

def run_audio_processing():
    with sd.Stream(callback=audio_callback, samplerate=44100, channels=1):
        while True:
            sd.sleep(1000)

# API Hooking Detection Functions
def check_api_hooking():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid = proc.info['pid']
            if pid <= 0:
                continue
            try:
                handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
                if handle:
                    modules = win32process.EnumProcessModules(handle)
                    for module in modules:
                        module_name = os.path.basename(win32process.GetModuleFileNameEx(handle, module))
                        if module_name.lower() in SUSPICIOUS_APIS:
                            logger.warning(f"Suspicious API found: {module_name} in process {proc.info['name']} (PID: {pid})")
                            terminate_process(proc.info['pid'], proc.info['name'])
                    win32api.CloseHandle(handle)
                else:
                    logger.error(f"Failed to open process with PID: {pid}")
            except Exception as e:
                logger.error(f"Error accessing process modules for PID: {pid}: {str(e)}")
        except (AccessDenied, NoSuchProcess, ZombieProcess) as e:
            logger.error(f"Error accessing process {proc.info['name']} (PID: {pid}): {str(e)}")

# Function to terminate processes
def terminate_process(pid, name):
    try:
        handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, False, pid)
        if handle:
            logger.info(f"Terminating process {name} (PID: {pid})")
            win32api.TerminateProcess(handle, 0)
            win32api.CloseHandle(handle)
        else:
            logger.error(f"Failed to open process with PID: {pid}")
    except Exception as e:
        logger.error(f"Failed to terminate process {name} (PID: {pid}): {str(e)}")

# Antivirus Functions (using VirusTotal API)
async def get_file_hash(file_path):
    """Get file hash to check if it has already been uploaded to VirusTotal."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

async def check_vt_file_status(session, file_hash):
    """Check if the file has been uploaded to VirusTotal before."""
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                return True  # File has been scanned before
            else:
                return False  # File not found
    except Exception as e:
        logger.error(f"Error checking file status: {e}")
        return False

async def scan_file(session, file_path):
    """Upload new file to VirusTotal."""
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        async with session.post(url, headers=headers, data={'file': open(file_path, 'rb')}) as response:
            if response.status == 200:
                result = await response.json()
                return result.get('data', {}).get('id')
            else:
                logger.error(f"Error uploading file: {await response.text()}")
                return None
    except Exception as e:
        logger.error(f"Exception while scanning file: {e}")
        return None

async def check_file_scan(session, report_id):
    """Check the status of the file scan."""
    url = f'https://www.virustotal.com/api/v3/analyses/{report_id}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                result = await response.json()
                if result['data']['attributes']['status'] == 'completed':
                    return result['data']['attributes']['results']
            return None
    except Exception as e:
        logger.error(f"Exception while checking file scan: {e}")
        return None

# Signed File Certificate Checking
def is_file_signed(file_path):
    """Check if a file is signed and return the certificate details."""
    try:
        cert = win32api.CryptQueryObject(
            win32api.CERT_QUERY_OBJECT_FILE, 
            file_path,
            win32api.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            win32api.CERT_QUERY_FORMAT_FLAG_BINARY,
            0
        )
        return cert
    except Exception as e:
        logger.error(f"Error checking certificate for file {file_path}: {str(e)}")
        return None

def check_signed_certificate(file_path):
    """Check if the signed certificate is trusted, and block if not."""
    cert = is_file_signed(file_path)
    if cert:
        logger.info(f"Certificate found for file {file_path}: {cert}")
        if not cert.is_trusted():
            logger.warning(f"Untrusted certificate for file {file_path}")
            block_file(file_path)
    else:
        logger.info(f"No certificate found for file {file_path}")

def block_file(file_path):
    """Block access to a file by modifying its permissions."""
    try:
        # Disable file access by removing permissions
        win32api.SetFileAttributes(file_path, win32con.FILE_ATTRIBUTE_HIDDEN)
        logger.info(f"Blocked file {file_path} by modifying permissions.")
    except Exception as e:
        logger.error(f"Error blocking file {file_path}: {str(e)}")

# Network Shares Detection
def get_network_shares():
    """Detect network shares available on the system."""
    shares = []
    try:
        result = subprocess.run(['net', 'view'], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith('\\\\'):
                shares.append(line.strip())
    except Exception as e:
        logger.error(f"Error getting network shares: {e}")
    return shares

# Overlay Detection and Process Termination
def detect_overlays():
    """Detect overlays and terminate suspicious processes."""
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid = proc.info['pid']
            name = proc.info['name'].lower()
            if any(keyword in name for keyword in OVERLAY_KEYWORDS):
                logger.warning(f"Detected overlay: {name} (PID: {pid})")
                terminate_process(pid, name)
        except (AccessDenied, NoSuchProcess, ZombieProcess) as e:
            logger.error(f"Error accessing process {proc.info['name']} (PID: {pid}): {str(e)}")

async def main_scan():
    drives = get_all_drives()
    shares = get_network_shares()
    file_paths = []
    for drive in drives:
        for root, _, files in os.walk(drive):
            for file in files:
                file_path = os.path.join(root, file)
                file_paths.append(file_path)
    for share in shares:
        for root, _, files in os.walk(share):
            for file in files:
                file_path = os.path.join(root, file)
                file_paths.append(file_path)
    
    async with aiohttp.ClientSession() as session:
        for file_path in file_paths:
            file_hash = await get_file_hash(file_path)
            already_scanned = await check_vt_file_status(session, file_hash)
            if not already_scanned:
                file_id = await scan_file(session, file_path)
                if file_id:
                    result = await check_file_scan(session, file_id)
                    if result:
                        logger.info(f"File {file_path} scanned with results: {result}")
            else:
                logger.info(f"File {file_path} already scanned.")

        with open(BLOCKED_URLS_FILE) as f:
            urls = f.readlines()
        for url in urls:
            url = url.strip()
            url_id = await scan_url(session, url)
            if url_id:
                result = await check_url_scan(session, url_id)
                if result:
                    logger.info(f"URL {url} scanned with results: {result}")
                    if result.get('malicious', False):
                        block_url(url)

# Main Function to Run All Tasks
def main():
    run_as_admin()

    # Start audio processing in a separate thread
    audio_thread = threading.Thread(target=run_audio_processing, daemon=True)
    audio_thread.start()

    # Check for API hooking in a loop
    api_hooking_thread = threading.Thread(target=check_api_hooking, daemon=True)
    api_hooking_thread.start()

    # Overlay detection and termination
    overlay_thread = threading.Thread(target=detect_overlays, daemon=True)
    overlay_thread.start()

    # Run antivirus scan in the main thread
    asyncio.run(main_scan())

if __name__ == "__main__":
    main()
