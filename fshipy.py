import requests
import json
import os
import logging
import datetime
from datetime import datetime
from requests.exceptions import RequestException
from concurrent.futures import ThreadPoolExecutor

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

MASTER_URL = "https://indexer.loadbalancer:9200/_cat/master?h=node"

try:
    MASTER_INDEXER = requests.get(MASTER_URL, verify=False)
    MASTER_INDEXER.raise_for_status()
    response_content = MASTER_INDEXER.text
except RequestException as e:
    logger.error('Error fetching master node: %s', e)
    raise SystemExit("Exiting due to an error")

# Set the OpenSearch endpoint
url_base = "http://" + response_content.strip() + ":9200/"

CHECKPOINT_FILE = '/etc/fshipy/pointer.pos'

def read_checkpoint():
    try:
        with open(CHECKPOINT_FILE, 'r') as checkpoint_file:
            return int(checkpoint_file.read().strip())
    except FileNotFoundError:
        return 0

def write_checkpoint(index):
    with open(CHECKPOINT_FILE, 'w') as checkpoint_file:
        checkpoint_file.write(str(index))

def send_bulk_request(url, headers, bulk_request):
    try:
        response = requests.post(url, headers=headers, data=bulk_request)
        response.raise_for_status()
        return response
    except RequestException as e:
        logger.error('Error sending bulk request: %s', e)
        raise  # Re-raise the exception to stop the script

def process_chunk(chunk_logs, chunk_start, url, headers):
    bulk_request = ""
    for index, log in enumerate(chunk_logs, start=chunk_start):
        action = {
            "index": {
                "_index": "saycure",
            }
        }
        bulk_request += json.dumps(action) + "\n" + log

    return send_bulk_request(url, headers, bulk_request)

def main():
    json_file_path = '/var/ossec/logs/alerts/alerts.json'
    current_date = datetime.now().strftime("%m-%d-%Y")
    index_name = f'saycure-alerts-{current_date}'
    url = f'{url_base}{index_name}/_bulk'
    headers = {'Content-Type': 'application/json'}
    chunk_size = 1000

    try:
        with open(json_file_path, 'r') as file:
            logs = file.readlines()

        last_processed_index = read_checkpoint()

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for i in range(last_processed_index, len(logs), chunk_size):
                chunk_logs = logs[i:i + chunk_size]
                future = executor.submit(process_chunk, chunk_logs, i + 1, url, headers)
                futures.append((i + 1, i + len(chunk_logs), future))

            for start, end, future in futures:
                try:
                    response = future.result()
                    logger.info('Bulk request successful for chunk %d-%d', start, end)
                    logger.debug('Response: %s', response.text)
                    last_processed_index = end
                    write_checkpoint(end)  # Update checkpoint after successful processing
                except Exception as e:
                    logger.error('Error processing chunk %d-%d: %s', start, end, e)

    except KeyboardInterrupt:
        logger.error('Script interrupted by user')
        raise SystemExit("Exiting due to user interruption")

if __name__ == "__main__":
    main()
