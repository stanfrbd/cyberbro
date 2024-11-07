from engines import abuseipdb, virustotal, ipinfo, spur_us, reverse_dns, google_safe_browsing
from utils import *
from flask import Flask, request, render_template, send_file, jsonify, send_from_directory
import pandas as pd
import threading
import time
import queue
import os

app = Flask(__name__)

# Global variable to store analysis results
results = []
analysis_in_progress = False  # Variable to track the state of the analysis
analysis_metadata = {}

def perform_analysis(observables, selected_engines):
    start_time = time.time()
    global results, analysis_in_progress, analysis_metadata
    results = []  # Reset results for each analysis
    analysis_in_progress = True

    result_queue = queue.Queue()

    def analyze_observable(observable, observable_type, index):
        result = {"observable": observable.strip(), "type": observable_type}
        result['reversed_success'] = False

        if "virustotal" in selected_engines and observable_type in ["MD5", "SHA1", "SHA256", "URL", "FQDN", "IPv4", "IPv6"]:
            result['virustotal'] = virustotal.query_virustotal(observable.strip())

        if "google_safe_browsing" in selected_engines and observable_type in ["URL", "FQDN", "IPv4", "IPv6"]:
            result['google_safe_browsing'] = google_safe_browsing.query_google_safe_browsing(observable.strip())

        if "reverse_dns" in selected_engines and observable_type in ["IPv4", "IPv6", "FQDN", "URL"]:
            result['reverse_dns'] = reverse_dns.reverse_dns(observable.strip())
            if observable_type == "FQDN" and result['reverse_dns'] is not None or observable_type == "URL" and result['reverse_dns'] is not None:
                result['reversed_success'] = True
                observable_type = "IPv4"
                observable = result["reverse_dns"]["reverse_dns"][-1]

        if "ipinfo" in selected_engines and observable_type in ["IPv4", "IPv6"]:
            result['ipinfo'] = ipinfo.query_ipinfo(observable.strip())

        if "abuseipdb" in selected_engines and observable_type in ["IPv4", "IPv6"]:
            result['abuseipdb'] = abuseipdb.query_abuseipdb(observable.strip())

        if "spur" in selected_engines and observable_type in ["IPv4", "IPv6"]:
            result['spur'] = spur_us.process_ip_with_spur(observable.strip())

        result_queue.put((index, result))

    threads = []
    for index, observable in enumerate(observables):
        observable_type = identify_observable_type(observable.strip())
        thread = threading.Thread(target=analyze_observable, args=(observable, observable_type, index))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Collect results from the queue and sort by index
    results = [None] * len(observables)
    while not result_queue.empty():
        index, result = result_queue.get()
        results[index] = result

    end_time = time.time()
    
    start_time_string = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time))
    end_time_string = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))

    analysis_duration = end_time - start_time
    # convert analysis duration to minutes and seconds
    analysis_duration_string = f"{int(analysis_duration // 60)} minutes, {analysis_duration % 60:.2f} seconds"
    
    analysis_metadata = {"start_time": start_time, "end_time": end_time, "start_time_string": start_time_string, "end_time_string": end_time_string ,"analysis_duration_string": analysis_duration_string, "analysis_duration": analysis_duration}
    analysis_in_progress = False  # End of analysis
    # Existing code to perform analysis
    print("Analysis results:", results)
    print("Analysis metadata:", analysis_metadata)
    print(f"Analysis took {analysis_metadata['analysis_duration_string']}")

# Main route for analysis
@app.route('/')
def index():
    return render_template('index.html', results=[])

@app.route('/analyze', methods=['POST'])
def analyze():
    observables = [obs for obs in request.form.get("observables", "").splitlines() if obs.strip()]
    selected_engines = request.form.getlist("engines")

    # Start analysis in a thread to avoid blocking
    analysis_thread = threading.Thread(target=perform_analysis, args=(observables, selected_engines))
    analysis_thread.start()

    # Display the waiting page
    return render_template('waiting.html'), 200  # Return 200 status for loading

@app.route('/results', methods=['GET'])
def show_results():
    return render_template('index.html', results=results, analysis_metadata=analysis_metadata)

@app.route('/is_analysis_complete', methods=['GET'])
def is_analysis_complete():
    return jsonify({'complete': not analysis_in_progress})

# Route to export results in CSV or Excel
@app.route('/export')
def export():
    format = request.args.get('format')
    
    # Prepare data for DataFrame
    data = []
    for result in results:
        ipinfo_data = result.get("ipinfo", {})
        spur_data = result.get("spur", {})
        abuseipdb_data = result.get("abuseipdb", {})
        virustotal_data = result.get("virustotal", {})
        google_safe_browsing_data = result.get("google_safe_browsing", {})

        row = {
            "observable": result.get("observable"),
            "type": result.get("type"),
            "rev_dns": result.get("reversed_success"),
            "ipinfo_cn": ipinfo_data.get("country"),
            "ipinfo_geo": ipinfo_data.get("geolocation"),
            "ipinfo_asn": ipinfo_data.get("asn").split(' ', 1)[0] if ipinfo_data.get("asn") else None,
            "ipinfo_org": ipinfo_data.get("asn").split(' ', 1)[1] if ipinfo_data.get("asn") else None,
            "spur_us_anon": spur_data.get("tunnels"),
            "a_ipdb_reports": abuseipdb_data.get("reports"),
            "a_ipdb_risk": abuseipdb_data.get("risk_score"),
            "vt_detect": virustotal_data.get("detection_ratio"),
            "vt_nb_detect": virustotal_data.get("total_malicious"),
            "vt_community": virustotal_data.get("community_score"),
            "gsb_threat": google_safe_browsing_data.get("threat_found")
        }
        data.append(row)
    
    df = pd.DataFrame(data)  # Convert results to DataFrame
    timestamp = time.strftime("%Y-%m-%d_%H_%M_%S", time.localtime())

    if format == 'csv':
        csv_path = f'{timestamp}_analysis_result.csv'
        df.to_csv(csv_path, index=False, sep=';')
        response = send_file(csv_path, as_attachment=True)
        # Delete the file after 10 seconds
        threading.Thread(target=lambda path: (time.sleep(10), os.remove(path)), args=(csv_path,)).start()
        return response

    elif format == 'excel':
        excel_path = f'{timestamp}_analysis_result.xlsx'
        with pd.ExcelWriter(excel_path, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Results')
            workbook  = writer.book
            worksheet = writer.sheets['Results']
            # Get the dimensions of the dataframe.
            (max_row, max_col) = df.shape
            # Apply autofilter to the worksheet.
            worksheet.auto_filter.ref = worksheet.dimensions
            # Adjust column widths based on the length of the longest entry in each column
            for col in worksheet.columns:
                max_length = 0
                column = col[0].column_letter # Get the column name
                for cell in col:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                adjusted_width = (max_length + 2)
                worksheet.column_dimensions[column].width = adjusted_width
        response = send_file(excel_path, as_attachment=True)
        # Delete the file after 10 seconds
        threading.Thread(target=lambda path: (time.sleep(10), os.remove(path)), args=(excel_path,)).start()
        return response

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'images'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
