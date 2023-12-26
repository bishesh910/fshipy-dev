import requests
import json
import os
import datetime
from datetime import datetime
import inotify.adapters
import urllib3
import logging
from logging.handlers import TimedRotatingFileHandler

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

current_DT = datetime.now()

formatted_datetime = current_DT.strftime("%Y-%m-%d %H:%M:%S")

# Set up logging with timed rotation
log_dir = '/var/log/fshipy'
log_file_path = os.path.join(log_dir, 'fshipy.log')

# Create the log directory if it doesn't exist
os.makedirs(log_dir, exist_ok=True)

# Set up TimedRotatingFileHandler
handler = TimedRotatingFileHandler(log_file_path, when="midnight", interval=1, backupCount=5)  # rotate daily, keep 5 backup files
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

logging.basicConfig(
    level=logging.INFO,
    handlers=[handler]
)

# Set the OpenSearch endpoint
url_base = os.environ['INDEXER_URL']

# Set the headers
headers = {
    'Content-Type': 'application/json',
}

# Set the authentication credentials if needed
auth = (os.environ['INDEXER_USER'], os.environ['INDEXER_PASSWORD'])

# Function to send the bulk request
def send_bulk_request(url, bulk_request):
    response = requests.post(url, headers=headers, auth=auth, data=bulk_request, verify=False)
    if response.status_code == 200:
        print(f'{formatted_datetime} Bulk request successful:')
        logging.info('Bulk request successful:')
    else:
        logging.error('Error in bulk request:')
        logging.error(f'Status Code: {response.status_code}')
        logging.error(response.text)

# Main function
def main():
    # Set the path to the JSON file
    file_path = '/var/ossec/logs/alerts/alerts.json'

    # Set the OpenSearch index URL
    current_date = datetime.now().strftime("%m-%d-%Y")
    index_name = f'saycure-{current_date}'
    url = f'{url_base}{index_name}/_bulk'

    # Set up inotify
    i = inotify.adapters.Inotify()

    # Add the file to watch for modifications
    i.add_watch(file_path)

    try:
        for event in i.event_gen(yield_nones=False):
            (_, type_names, path, filename) = event
            if "IN_MODIFY" in type_names:
                print(f'File {path}/{filename} has been modified. Sending bulk request...')
                with open(file_path, 'r') as file:
                    logs = file.readlines()

                # Prepare the bulk request
                bulk_request = ""
                for index, log in enumerate(logs, start=1):
                    action = {
                        "index": {
                            "_index": index_name,
                        }
                    }
                    bulk_request += json.dumps(action) + "\n" + log + "\n"

                # Send the bulk request
                send_bulk_request(url, bulk_request)

    except KeyboardInterrupt:
        pass
    finally:
        i.remove_watch(file_path)

if __name__ == "__main__":
    main()