#!/usr/bin/python3

from typing import Optional
from urllib.request import Request, urlopen
import argparse
import urllib.error
from sys import exit
from termcolor import colored
from urllib.parse import urlparse
import os
import concurrent.futures
import queue
import threading
import subprocess
import json

# Slack Bot Token and Channel ID
VW_SLACK_TOKEN = 'SLACK_BOT_TOKEN_WITH_WRITE_INCOMING_HOOK_ACCESS'
VW_SLACK_CHANNEL = 'CHANNEL_ID_HERE'

# Global variables
vuln = False
hdr = {'User-Agent': 'Mozilla/5.0'}
results_dir = 'results'
result_queue = queue.Queue()

def send_to_slack_worker():
    while True:
        item = result_queue.get()
        if item is None:  # None is the signal to stop the worker
            break
        domain, poc_filename, serial_no = item
        send_to_slack(domain, poc_filename, serial_no)
        result_queue.task_done()

def send_to_slack(domain, poc_filename, serial_no):
    try:
        # Remove 'http://' or 'https://' from the domain and format the title
        clean_domain = domain.replace('http://', '').replace('https://', '')

        # Command to send the file and message to Slack using curl
        command = [
            "curl",
            "-F", f"file=@{poc_filename}",
            "-F", f"initial_comment=*ClickJacking Vulnerability Detected for {clean_domain}*\n>Exploit code file that contains the .html code is attached below.",
            "-F", f"channels={VW_SLACK_CHANNEL}",
            "-H", f"Authorization: Bearer {VW_SLACK_TOKEN}",
            "https://slack.com/api/files.upload"
        ]

        # Execute the curl command
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0:
            print(colored(f"{serial_no}. Exploit Code for {domain} sent to Slack successfully.", "blue"))
        else:
            raise ValueError(f"Curl command failed: {result.stderr}")

    except Exception as e:
        print(f"Error sending file to Slack: {e}")
        # Log to file if possible
        try:
            with open(f'{results_dir}/log.txt', 'a') as lf:
                lf.write(f"Error sending file to Slack for {domain}: {e}\n")
        except:
            pass

def check_domain(t, serial_no, log_file_path=None):
    """Check if a domain is vulnerable to clickjacking.
    
    Args:
        t: URL to check
        serial_no: Serial number for logging
        log_file_path: Optional path to log file
        
    Returns:
        dict: Result dictionary with vulnerability status and details
    """
    if not t.startswith(('http://', 'https://')):
        t = "https://" + t  # Assuming https if no scheme is provided

    # Ensure results directory exists
    if not os.path.exists(results_dir):
        os.makedirs(results_dir, exist_ok=True)

    try:
        req = Request(t, headers=hdr)
        response = urlopen(req, timeout=10)
        status_code = response.getcode()

        if status_code == 200:
            filename = urlparse(t).netloc
            headers = response.info()

            if 'X-Frame-Options' not in headers and 'x-frame-options' not in headers:
                # print(colored(f"{serial_no}. Target: {t} is Vulnerable", "green"))
                # print(colored(f"Generating {filename}.html Exploit Code File", "yellow"))

                poc = f"""
                <html>
                <head><title>Clickjack Exploit Code page</title></head>
                <body>
                <p>Website is vulnerable to clickjacking!</p>
                <iframe src="{t}" width="500" height="500"></iframe>
                </body>
                </html>
                """

                if ":" in filename:
                    filename = filename.split(':')[0]

                poc_filename = f"{results_dir}/{filename}.html"
                with open(poc_filename, "w") as pf:
                    pf.write(poc)

                # print(colored(f"{serial_no}. Clickjacking Exploit Code file Created Successfully, Open {poc_filename} to get the Exploit Code", "blue"))

                # Add the result to the queue if it exists
                try:
                    result_queue.put((t, poc_filename, serial_no))
                except:
                    pass  # Queue may not exist in standalone mode

                return {
                    "vulnerable": True,
                    "url": t,
                    "poc_file": poc_filename,
                    "message": f"Vulnerable - POC created at {poc_filename}"
                }

            else:
                print(colored(f"{serial_no}. Target: {t} is not Vulnerable", "red"))
                print("Testing Other URLs in the List")
                return {
                    "vulnerable": False,
                    "url": t,
                    "message": "Not vulnerable - X-Frame-Options header present"
                }
        else:
            msg = f"Target {t} is not active, status code: {status_code}"
            print(colored(f"{serial_no}. {msg}", "red"))
            if log_file_path:
                with open(log_file_path, 'a') as lf:
                    lf.write(msg + "\n")
            return {
                "vulnerable": False,
                "url": t,
                "message": msg
            }

    except KeyboardInterrupt:
        print("No Worries, I'm here to handle your Keyboard Interrupts\n")
        return {
            "vulnerable": False,
            "url": t,
            "message": "Interrupted by user"
        }
    except urllib.error.URLError as e:
        msg = f"Target {t} is unreachable: {e.reason}"
        print(colored(f"{serial_no}. {msg}", "red"))
        if log_file_path:
            with open(log_file_path, 'a') as lf:
                lf.write(msg + "\n")
        return {
            "vulnerable": False,
            "url": t,
            "message": msg
        }
    except Exception as e:
        msg = f"Exception Occurred with Target {t}: {e}"
        print(f"{serial_no}. {msg}")
        if log_file_path:
            with open(log_file_path, 'a') as lf:
                lf.write(msg + "\n")
        return {
            "vulnerable": False,
            "url": t,
            "message": msg
        }

def main():
    """Main function for CLI usage."""
    # Print banner
    print(r'''                                                            
  ____ _     ___ ____ _  __  _            _            
 / ___| |   |_ _/ ___| |/ / (_) __ _  ___| | __  
| |   | |    | | |   | ' /  | |/ _` |/ __| |/ /  
| |___| |___ | | |___| . \  | | (_| | (__|   <   
 \____|_____|___\____|_|\_\_/ |\__,_|\___|_|\_\/       
                          |__/            
                            
                          By: Chirag Agrawal
    Reach me :-
            {+} Twitter: __Raiders
            {+} Github : Raiders0786

#################### Testing Started ####################
''')
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description='This Tool will automate & Check if the List of URLs in the file are Vulnerable to Clickjacking Attack & will make a POC for the Vulnerable URL')
    parser.add_argument(
        "-f", type=str, help="Pass a list of Domains stored in a File", required=True)
    
    args = parser.parse_args()
    
    # Setup log file
    log_file_path = f'{results_dir}/log.txt'
    if not os.path.exists(results_dir):
        os.makedirs(results_dir, exist_ok=True)
    
    # Start the worker thread
    threading.Thread(target=send_to_slack_worker, daemon=True).start()

    try:
        with open(args.f, 'r') as d:
            targets = [target.strip('\n') for target in d.readlines()]

        # Process domains concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for serial_no, target in enumerate(targets, start=1):
                executor.submit(check_domain, target, serial_no, log_file_path)

        # Wait for the queue to be empty before exiting
        result_queue.join()
        print("All Targets Tested Successfully !!")

    except Exception as e:
        print(f"Error: {e}")
        print("[*] Usage: python3 clickJackPoc.py -f <file_name>")
        print("[*] The Code might not have worked for you, please retry & try the --help option to know more")
    finally:
        # Stop the worker thread
        result_queue.put(None)
        exit(0)

def clickjack_url_detect(url: str) -> Optional[str]:
    """Detect if a URL is vulnerable to clickjacking.
    
    This is a standalone function for programmatic use.
    
    Args:
        url: The URL to check for clickjacking vulnerability
        
    Returns:
        JSON string with vulnerability status and details, or None on error
    """
    try:
        result = check_domain(url, 1, log_file_path=f'{results_dir}/log.txt')
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({
            "vulnerable": False,
            "url": url,
            "message": f"Error: {str(e)}"
        }, indent=2)
    
if __name__ == "__main__":
    main()
