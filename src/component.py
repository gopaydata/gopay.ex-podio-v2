import logging
from datetime import datetime, timedelta
import json
import pandas as pd
import requests
from keboola.component.base import ComponentBase
import keboola.component.exceptions

# Configuration variables
KEY_CLIENT_ID = '#client_id'
KEY_CLIENT_SECRET = '#client_secret'
KEY_USERNAME = 'username'
KEY_PASSWORD = '#password'
KEY_APP_ID = 'app_id'

# List of mandatory parameters
REQUIRED_PARAMETERS = [KEY_CLIENT_ID, KEY_CLIENT_SECRET, KEY_USERNAME, KEY_PASSWORD, KEY_APP_ID]

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


def transform_podio_items(items):
    transformed_data = []
    for item in items:
        item_data = {
            'item_id': item['item_id'],
            'external_id': item.get('external_id', None),
            'request_number': item.get('app_item_id_formatted', None),
            'request_link': item.get('link', None),
            'title': item['title'],
            'created_on': item['created_on'],
            'last_event_on': item.get('last_event_on', None),
            'created_by_name': item['created_by']['name'] if 'created_by' in item else None,
            'realizuje_name': None,
            'stav_text': None,
            'datum_zmeny_stavu': None,
            'kontrola_splneni_text': None,
            'oblast_text': None,
            'priorita_text': None,
            'schvaleni_text': None,
            'prostredi_text': None,
            'signifikantni_zmena': None,
            'poznamky_text': None,
            'files': None,
            'tags': None,
            'tasks': None,
            'jira_project_text': None,
            'jira_link': None,
            'pozadavek_text': None,
            'zadani_text': None,
            'zainteresovane_osoby': None
        }

        # Retrieve custom fields (fields)
        for field in item['fields']:
            field_label = field['label']
            field_values = field['values']

            if field_label == 'Požadavek':
                item_data['pozadavek_text'] = field_values[0]['value'] if field_values else None
            elif field_label == 'Stav':
                item_data['stav_text'] = field_values[0]['value']['text'] if field_values else None
                if item.get('last_event_on'):
                    item_data['datum_zmeny_stavu'] = item['last_event_on']
            elif field_label == 'Kontrola splnění požadavku':
                item_data['kontrola_splneni_text'] = field_values[0]['value']['text'] if field_values else None
            elif field_label == 'Oblast':
                item_data['oblast_text'] = field_values[0]['value']['text'] if field_values else None
            elif field_label == 'Klasifikace':
                item_data['priorita_text'] = field_values[0]['value']['text'] if field_values else None
            elif field_label == 'Schválení':
                item_data['schvaleni_text'] = field_values[0]['value']['text'] if field_values else None
            elif field_label == 'Prostředí':
                # Prostředí může být vícenásobné, takže extrahujeme všechna prostředí jako text
                item_data['prostredi_text'] = ', '.join([env['value']['text'] for env in field_values])
            elif field_label == 'Signifikantní změna':
                item_data['signifikantni_zmena'] = field_values[0]['value']['text'] if field_values else None
            elif field_label == 'Poznámky':
                item_data['poznamky_text'] = field_values[0]['value'] if field_values else None
            elif field_label == 'Realizuje':
                item_data['realizuje_name'] = field_values[0]['value']['name'] if field_values else None
            elif field_label == 'Zainteresované osoby':
                item_data['zainteresovane_osoby'] = ', '.join([person['value']['name'] for person in field_values])
            elif field_label == 'Jira Link':
                item_data['jira_link'] = field_values[0]['value'] if field_values else None
            elif field_label == 'Zadání':
                item_data['zadani_text'] = field_values[0]['value'] if field_values else None

        # Collect files, tags, and tasks if available
        if 'files' in item and item['files']:
            item_data['files'] = ', '.join([file['name'] for file in item['files']])
        if 'tags' in item and item['tags']:
            item_data['tags'] = ', '.join(item['tags'])
        if 'tasks' in item and item['tasks']:
            item_data['tasks'] = ', '.join([task['title'] for task in item['tasks']])

        transformed_data.append(item_data)

    # Convert to Pandas DataFrame
    df = pd.DataFrame(transformed_data)
    logging.info(f"Data transformation completed, records: {len(df)}")
    return df


def create_manifest(file_path, delimiter='\t', enclosure='"'):
    """
    Vytvoří manifest pro CSV soubor.
    """
    manifest = {
        "delimiter": delimiter,
        "enclosure": enclosure
    }
    manifest_path = f"{file_path}.manifest"
    with open(manifest_path, 'w', encoding='utf-8') as manifest_file:
        json.dump(manifest, manifest_file)
    logging.info(f"Manifest file created at {manifest_path}.")


class Component(ComponentBase):
    """
    Extends base class for general Python components. Initializes the CommonInterface
    and performs configuration validation.
    """

    def __init__(self):
        super().__init__()
        self.access_token = None
        self.authenticate_podio()

    def authenticate_podio(self):
        params = self.configuration.parameters
        logging.info("Authenticating to Podio API")
        auth_url = 'https://podio.com/oauth/token'
        auth_data = {
            'grant_type': 'password',
            'client_id': params.get(KEY_CLIENT_ID),
            'client_secret': params.get(KEY_CLIENT_SECRET),
            'username': params.get(KEY_USERNAME),
            'password': params.get(KEY_PASSWORD),
        }

        response = requests.post(auth_url, data=auth_data)
        if response.status_code == 200:
            auth_json = response.json()
            logging.info("Successful authentication")
            self.access_token = auth_json['access_token']
        else:
            logging.error("Authentication error: " + response.text)
            raise Exception("Authentication failed: " + response.text)

    def get_podio_items(self, app_id, limit=100, offset=0):
        url = f'https://api.podio.com/item/app/{app_id}/'
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        params = {
            'limit': limit,
            'offset': offset
        }

        logging.info(f"Retrieving items from Podio, limit: {limit}, offset: {offset}")
        response = requests.get(url, headers=headers, params=params)

        if response.status_code != 200:
            logging.error(f"Error retrieving items: {response.text}")
            raise Exception(f"Failed to retrieve items: {response.text}")

        return response.json().get('items', [])

    def get_all_podio_items(self, app_id, max_items=1000, batch_size=100):
        """
        Načítá data z Podio API po dávkách a ukládá je postupně do souboru.
        """
        offset = 0
        total_fetched = 0

        # Výstupní cesta k souboru
        pozadavky = self.create_out_table_definition('items.csv')
        out_table_path = pozadavky.full_path
        create_manifest(out_table_path)  # Vytvoření manifestu pro první dávku

        logging.info(f"Starting batch processing with batch_size={batch_size}")

        while total_fetched < max_items:
            batch_items = self.get_podio_items(app_id, limit=batch_size, offset=offset)
            if not batch_items:
                logging.info("No more items to fetch. Ending process.")
                break

            # Filtrování položek z posledních 10 dnů
            filtr_date = datetime.now() - timedelta(days=10)
            items_last_10_days = [
                item for item in batch_items
                if datetime.strptime(item['last_event_on'], '%Y-%m-%d %H:%M:%S') >= filtr_date
            ]

            # Transformace položek a přejmenování sloupců
            df_podio = transform_podio_items(items_last_10_days)
            column_rename_map = {
                'item_id': 'item_id',
                'external_id': 'external_id',
                'request_number': 'request_number',
                'request_link': 'request_link',
                'title': 'title',
                'created_on': 'created_on',
                'last_event_on': 'last_event_on',
                'created_by_name': 'created_by',
                'realizuje_name': 'responsible',
                'stav_text': 'status',
                'datum_zmeny_stavu': 'status_change_date',
                'kontrola_splneni_text': 'requirement_fulfillment_check',
                'oblast_text': 'area',
                'priorita_text': 'priority',
                'schvaleni_text': 'approval',
                'prostredi_text': 'environment',
                'signifikantni_zmena': 'significant_change',
                'poznamky_text': 'notes',
                'files': 'files',
                'tags': 'tags',
                'tasks': 'tasks',
                'jira_project_text': 'jira_project',
                'jira_link': 'jira_link',
                'pozadavek_text': 'requirement',
                'zadani_text': 'assignment',
                'zainteresovane_osoby': 'interested_persons'
            }

            df_podio.rename(columns=column_rename_map, inplace=True)

            # Uložení dávky do souboru
            if not df_podio.empty:
                write_mode = 'a' if total_fetched > 0 else 'w'
                df_podio.to_csv(out_table_path, sep='\t', index=False, mode=write_mode, header=(write_mode == 'w'))
                logging.info(f"Saved {len(df_podio)} records to {out_table_path}.")

            # Aktualizace offsetu a celkového počtu načtených položek
            offset += batch_size
            total_fetched += len(batch_items)

    def run(self):
        # pozadavky = self.create_out_table_definition('items.csv')

        app_id = self.configuration.parameters.get(KEY_APP_ID)
        self.get_all_podio_items(app_id, max_items=10000)


# Main entry point
if __name__ == "__main__":
    try:
        comp = Component()
        comp.execute_action()
    except keboola.component.exceptions.UserException as exc:
        logging.exception(exc)
        exit(1)
    except Exception as exc:
        logging.exception(exc)
        exit(2)
