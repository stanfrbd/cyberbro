import logging
import threading
import time
from pathlib import Path

import pandas as pd
from flask import send_file

from engines import get_engine_instances
from utils.config import get_config

logger = logging.getLogger(__name__)

# We need access to the engine instances to format the rows.
# In a real app, you might inject this.
secrets = get_config()
LOADED_ENGINES = get_engine_instances(secrets, {"http": secrets.proxy_url}, secrets.ssl_verify)


def prepare_row(result, selected_engines):
    row = {"observable": result.get("observable"), "type": result.get("type")}

    # Standard Engines
    for engine_name in selected_engines:
        engine = LOADED_ENGINES.get(engine_name)
        if engine:
            engine_data = result.get(engine_name)
            # Delegate formatting to the engine itself
            row.update(engine.create_export_row(engine_data))

    # Handle Chrome Extension specifically if it's not a standard engine yet
    if result.get("type") == "CHROME_EXTENSION":
        extension_data = result.get("extension")
        row["extension_name"] = extension_data.get("name") if extension_data else None

    return row


def prepare_data_for_export(analysis_results):
    data = []
    for result in analysis_results.results:
        row = prepare_row(result, analysis_results.selected_engines)
        data.append(row)
    return data


# ... (Keep the rest of the export_to_csv / export_to_excel functions exactly as they were) ...
def export_to_csv(data, timestamp):
    df = pd.DataFrame(data)
    csv_path = f"{timestamp}_analysis_result.csv"
    df.to_csv(csv_path, index=False, sep=";")
    threading.Thread(target=lambda path: (time.sleep(10), Path(path).unlink()), args=(csv_path,)).start()
    return send_file(csv_path, as_attachment=True)


def export_to_excel(data, timestamp):
    df = pd.DataFrame(data)
    excel_path = f"{timestamp}_analysis_result.xlsx"
    with pd.ExcelWriter(excel_path, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Results")
        worksheet = writer.sheets["Results"]
        worksheet.auto_filter.ref = worksheet.dimensions
        for col in worksheet.columns:
            max_length = 0
            column = col[0].column_letter
            for cell in col:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except Exception as e:
                    logger.error("Error exporting to Excel, column %s, cell %s, '%s'", column, cell, e, exc_info=True)
            worksheet.column_dimensions[column].width = max_length + 2
    response = send_file(excel_path, as_attachment=True)
    threading.Thread(target=lambda path: (time.sleep(10), Path(path).unlink()), args=(excel_path,)).start()
    return response
