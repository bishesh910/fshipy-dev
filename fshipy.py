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
import subprocess


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

EPOCH_FILE = '/etc/fshipy/epoch/epoch.pos'
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

def reset_checkpoint():
    logger.info('Rotated index for today')
    write_checkpoint(0)

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
    bulk_request = []
    num_logs = len(chunk_logs)  # Get the number of logs in the chunk
    logger.info('Processing chunk %d-%d with %d logs', chunk_start, chunk_start + num_logs, num_logs)

    for index, log in enumerate(chunk_logs, start=chunk_start):
        try:
            action = {
                "index": {
                    "_index": index_name,
                }
            }
            log_entry = {"index": {"_index": index_name}}  # Include the index action
            log_entry.update(json.loads(log))  # Add the log data

            # Debug log statement to print the content of each log
            logger.debug('Processing log: %s', json.dumps(log_entry))

            bulk_request.append(json.dumps(action))
            bulk_request.append(json.dumps(log_entry))
        except json.JSONDecodeError as json_error:
            # Debug log statement to print the specific log causing the error
            logger.error('Error decoding JSON for log at position %d: %s', index + 1, str(json_error))
            logger.error('Problematic log: %s', log)

    try:
        # Create the entire bulk request by joining the log entries with newline characters
        bulk_request_text = "\n".join(bulk_request) + "\n"

        # Debug log statement to print the content of the bulk request
        logger.debug('Bulk request: %s', bulk_request_text)

        return send_bulk_request(url, headers, auth, bulk_request_text)

    except Exception as e:
        # Debug log statement to print the specific log causing the error
        logger.error('Error processing chunk %d-%d: %s', chunk_start, chunk_start + len(chunk_logs), str(e))
        logger.error('Problematic log: %s', log)

        # Raise the exception again to terminate the script
        raise


def read_last_processed_epoch_time():
    try:
        with open(EPOCH_FILE, 'r') as epoch_file:
            return int(epoch_file.read().strip())
    except FileNotFoundError:
        return 0

def write_last_processed_epoch_time(index):
    with open(EPOCH_FILE, 'w') as epoch_file:
        epoch_file.write(str(index))

def rotationfilecheck():
     command = "stat -c %W /var/ossec/logs/alerts/alerts.json"
     birth_of_file = int(subprocess.check_output(command, shell=True, text=True))
     return birth_of_file

def main():
    json_file_path = '/var/ossec/logs/alerts/alerts.json'
    interval_seconds = 10  # Adjust this value based on your needs
    auth = ('admin', 'CRsaycure2k23')
    chunk_size = 500
    last_processed_epoch_time = read_last_processed_epoch_time()

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

                with ThreadPoolExecutor(max_workers=5) as executor:
                    futures = []
                    birth_of_file = rotationfilecheck()
                    if last_processed_epoch_time < birth_of_file:
                        if read_checkpoint() > len(logs):
                            reset_checkpoint()

                    last_processed_index = read_checkpoint()
                    for i in range(last_processed_index, len(logs), chunk_size):
                        # Check if a new day has started
                        current_date = datetime.now().strftime("%m-%d-%Y")
                        index_name = f'saycure-{current_date}'
                        url = f'{url_base}{index_name}/_bulk'
                        chunk_logs = logs[i:i + chunk_size]
                        future = executor.submit(process_chunk, chunk_logs, i + 1, url, headers, auth, index_name)
                        futures.append((i + 1, i + len(chunk_logs), future))

                    for start, end, future in futures:
                        try:
                            response = future.result()
                            response.raise_for_status()
                            logger.info('Bulk request successful for chunk %d-%d at %d', start, end, int(time.time()))
                            logger.debug('Response: %s', response.text)
                            last_processed_index = end
                            last_processed_timestamp = int(time.time())
                            write_checkpoint(end)  # Update checkpoint after successful processing
                            write_last_processed_epoch_time(last_processed_timestamp)
                        except Exception as e:
                            logger.error(f'Error processing chunk %d-%d: %s', start, end, str(e))
                            if hasattr(e, 'response'):
                                logger.error('Response content: %s', e.response.text)
                            logger.debug('Chunk content: %s', '\n'.join(chunk_logs))  # Add this line for debugging

            time.sleep(interval_seconds)  # Wait before checking again

    except KeyboardInterrupt:
        logger.error('Script interrupted by user')
        raise SystemExit("Exiting due to user interruption")

if __name__ == "__main__":
    main()
