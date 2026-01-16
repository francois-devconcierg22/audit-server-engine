import csv
import requests
import os
from collections import defaultdict

NOTION_TOKEN = os.environ["NOTION_TOKEN"]
DATABASE_ID = os.environ["NOTION_DATABASE_ID"]

HEADERS = {
    "Authorization": f"Bearer {NOTION_TOKEN}",
    "Notion-Version": "2022-06-28",
    "Content-Type": "application/json"
}

def load_referential(csv_path):
    values = defaultdict(list)
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            values[row["property"]].append(row["value"])
    return values

def update_property(property_name, values):
    options = [{"name": v} for v in values]
    payload = {
        "properties": {
            property_name: {
                "select": {
                    "options": options
                }
            }
        }
    }

    r = requests.patch(
        f"https://api.notion.com/v1/databases/{DATABASE_ID}",
        headers=HEADERS,
        json=payload
    )

    if r.status_code != 200:
        raise RuntimeError(f"Erreur Notion sur {property_name}: {r.text}")

def main():
    referential = load_referential("referential/notion_select_values.csv")
    for prop, values in referential.items():
        update_property(prop, values)
        print(f"✔ Propriété mise à jour : {prop}")

if __name__ == "__main__":
    main()
