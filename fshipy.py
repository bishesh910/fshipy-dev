import requests
import json
import os
import logging
import datetime
from datetime import datetime
from requests.exceptions import RequestException
from concurrent.futures import ThreadPoolExecutor
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging to write to a file
log_file_path = '/etc/fshipy/log/fshipy.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(),  # Log to console
        logging.FileHandler(log_file_path)  # Log to file
    ],
    force=True  # Ensure that the root logger is reconfigured
)
logger = logging.getLogger(__name__)

MASTER_URL = "https://loadbalancer.saycure.io:9200/_cat/master?h=node"
auth_credentials = ('admin', 'CRsaycure2k23')
try:
    MASTER_INDEXER = requests.get(MASTER_URL, auth=auth_credentials, verify=False)
    MASTER_INDEXER.raise_for_status()
    response_content = MASTER_INDEXER.text
except RequestException as e:
    logger.error('Error fetching master node: %s', e)
    raise SystemExit("Exiting due to an error")

# Set the OpenSearch endpoint
url_base = "https://" + response_content.strip() + ":9200/"  # Change from http to https

CHECKPOINT_FILE = '/etc/fshipy/pointer/pointer.pos'

def read_checkpoint():
    try:
        with open(CHECKPOINT_FILE, 'r') as checkpoint_file:
            return int(checkpoint_file.read().strip())
    except FileNotFoundError:
        return 0

def write_checkpoint(index):
    with open(CHECKPOINT_FILE, 'w') as checkpoint_file:
        checkpoint_file.write(str(index))

def send_bulk_request(url, headers, auth, bulk_request):
    try:
        response = requests.post(url, headers=headers, auth=auth, data=bulk_request, verify=False)
        response.raise_for_status()
        return response
    except RequestException as e:
        logger.error('Error sending bulk request: %s', e)
        logger.debug('Bulk Request Content: %s', bulk_request)  # Add this line for debugging
        raise

def process_chunk(chunk_logs, chunk_start, url, headers, auth, index_name):
    bulk_request = ""
    for index, log in enumerate(chunk_logs, start=chunk_start):
        action = {
            "index": {
                "_index": index_name,
            }
        }
        bulk_request += json.dumps(action) + "\n" + log

    # Add a newline character to terminate the bulk request
    bulk_request += "\n"

    return send_bulk_request(url, headers, auth, bulk_request)

def main():
    json_file_path = '/var/ossec/logs/alerts/alerts.json'
    interval_seconds = 1  # Adjust this value based on your needs
    auth = ('admin', 'CRsaycure2k23')
    chunk_size = 500

    try:
        last_modified_time = 0  # Initialize last_modified_time outside the loop

        while True:
            # Check if the file has been modified
            current_modified_time = os.path.getmtime(json_file_path)
            if current_modified_time != last_modified_time:
                last_modified_time = current_modified_time
                headers = {'Content-Type': 'application/json'}

                with open(json_file_path, 'r') as file:
                    logs = file.readlines()

                last_processed_index = read_checkpoint()

                with ThreadPoolExecutor(max_workers=5) as executor:
                    futures = []
                    for i in range(last_processed_index, len(logs), chunk_size):
                        current_date = datetime.now().strftime("%m-%d-%Y")
                        index_name = f'saycure-{current_date}'  # Modified index name
                        url = f'{url_base}{index_name}/_bulk'
                        chunk_logs = logs[i:i + chunk_size]
                        future = executor.submit(process_chunk, chunk_logs, i + 1, url, headers, auth, index_name)
                        futures.append((i + 1, i + len(chunk_logs), future))

                    for start, end, future in futures:
                        try:
                            response = future.result()
                            response.raise_for_status()
                            logger.info('Bulk request successful for chunk %d-%d', start, end)
                            logger.debug('Response: %s', response.text)
                            last_processed_index = end
                            write_checkpoint(end)  # Update checkpoint after successful processing
                        except Exception as e:
                            logger.error(f'Error processing chunk %d-%d: %s', start, end, str(e))
                            if hasattr(e, 'response'):
                                logger.error('Response content: %s', e.response.text)

            time.sleep(interval_seconds)  # Wait before checking again

    except KeyboardInterrupt:
        logger.error('Script interrupted by user')
        raise SystemExit("Exiting due to user interruption")

if __name__ == "__main__":
    main()
