import pandas as pd
import threading
import time
import os
from flask import send_file

def prepare_row(result, selected_engines):
    """
    Prepares a dictionary (row) with data extracted from the result dictionary based on the selected engines.
    Args:
        result (dict): A dictionary containing various data sources and their respective information.
        selected_engines (list): A list of strings representing the selected engines to include in the row.
    Returns:
        dict: A dictionary containing the prepared row with data from the result dictionary based on the selected engines.
    """
    rev_dns_data = result.get("reverse_dns", {})
    ipinfo_data = result.get("ipinfo", {})
    abuseipdb_data = result.get("abuseipdb", {})

    row = {
        "observable": result.get("observable"),
        "type": result.get("type")
    }

    # Will be at the end of the report if there are other observable types
    if result.get("type") == "CHROME_EXTENSION":
        extension_data = result.get("extension")
        row["extension_name"] = extension_data.get("name") if extension_data else None

    if "reverse_dns" in selected_engines:
        row["rev_dns"] = result.get("reversed_success") if rev_dns_data else None
        row["dns_lookup"] = rev_dns_data.get("reverse_dns") if rev_dns_data else None

    if "ipquery" in selected_engines:
        ipquery_data = result.get("ipquery", {})
        row["ipq_cn"] = ipquery_data.get("country_code") if ipquery_data else None
        row["ipq_country"] = ipquery_data.get("country_name") if ipquery_data else None
        row["ipq_geo"] = ipquery_data.get("geolocation") if ipquery_data else None
        row["ipq_asn"] = ipquery_data.get("asn") if ipquery_data else None
        row["ipq_isp"] = ipquery_data.get("isp") if ipquery_data else None
        row["ipq_vpn"] = ipquery_data.get("is_vpn") if ipquery_data else None
        row["ipq_tor"] = ipquery_data.get("is_tor") if ipquery_data else None
        row["ipq_proxy"] = ipquery_data.get("is_proxy") if ipquery_data else None

    if "ipinfo" in selected_engines:
        row["ipinfo_cn"] = ipinfo_data.get("country_code") if ipinfo_data else None
        row["ipinfo_country"] = ipinfo_data.get("country_name") if ipinfo_data else None
        row["ipinfo_geo"] = ipinfo_data.get("geolocation") if ipinfo_data else None
        asn_data = ipinfo_data.get("asn").split(' ', 1) if ipinfo_data.get("asn") else []
        row["ipinfo_asn"] = asn_data[0] if len(asn_data) > 0 else None
        row["ipinfo_org"] = asn_data[1] if len(asn_data) > 1 else None

    if "abuseipdb" in selected_engines:
        row["a_ipdb_reports"] = abuseipdb_data.get("reports") if abuseipdb_data else None
        row["a_ipdb_risk"] = abuseipdb_data.get("risk_score") if abuseipdb_data else None

    if "rdap" in selected_engines:
        rdap_data = result.get("rdap", {})
        row["rdap_abuse"] = rdap_data.get("abuse_contact") if rdap_data else None
        row["rdap_registrar"] = rdap_data.get("registrar") if rdap_data else None
        row["rdap_org"] = rdap_data.get("organization") if rdap_data else None
        row["rdap_registrant"] = rdap_data.get("registrant") if rdap_data else None
        row["rdap_registrant_email"] = rdap_data.get("registrant_email") if rdap_data else None
        row["rdap_ns"] = rdap_data.get("name_servers") if rdap_data else None
        row["rdap_creation"] = rdap_data.get("creation_date") if rdap_data else None
        row["rdap_expiration"] = rdap_data.get("expiration_date") if rdap_data else None
        row["rdap_update"] = rdap_data.get("update_date") if rdap_data else None

    if "abusix" in selected_engines:
        abusix_data = result.get("abusix", {})
        row["abusix_abuse"] = abusix_data.get("abuse") if abusix_data else None

    if "threatfox" in selected_engines:
        threatfox_data = result.get("threatfox", {})
        row["tf_count"] = threatfox_data.get("count") if threatfox_data else None
        row["tf_malware"] = threatfox_data.get("malware_printable") if threatfox_data else None

    if "virustotal" in selected_engines:
        virustotal_data = result.get("virustotal", {})
        row["vt_detect"] = virustotal_data.get("detection_ratio") if virustotal_data else None
        row["vt_nb_detect"] = virustotal_data.get("total_malicious") if virustotal_data else None
        row["vt_community"] = virustotal_data.get("community_score") if virustotal_data else None

    if "alienvault" in selected_engines:
        alienvault_data = result.get("alienvault", {})
        row["alienvault_pulses"] = alienvault_data.get("count") if alienvault_data else None
        row["alienvault_malwares"] = alienvault_data.get("malware_families") if alienvault_data else None
        row["alienvault_adversary"] = alienvault_data.get("adversary") if alienvault_data else None

    if "spur" in selected_engines:
        spur_data = result.get("spur", {})
        row["spur_us_anon"] = spur_data.get("tunnels") if spur_data else None
    
    if "webscout" in selected_engines:
        webscout_data = result.get("webscout", {})
        row["ws_risk"] = webscout_data.get("risk_score") if webscout_data else None
        row["ws_is_proxy"] = webscout_data.get("is_proxy") if webscout_data else None
        row["ws_is_tor"] = webscout_data.get("is_tor") if webscout_data else None
        row["ws_is_vpn"] = webscout_data.get("is_vpn") if webscout_data else None
        row["ws_cn"] = webscout_data.get("country_code") if webscout_data else None
        row["ws_country"] = webscout_data.get("country_name") if webscout_data else None
        row["ws_location"] = webscout_data.get("location") if webscout_data else None
        row["ws_hostnames"] = webscout_data.get("hostnames") if webscout_data else None
        row["ws_domains_on_ip"] = webscout_data.get("domains_on_ip") if webscout_data else None
        row["ws_network_type"] = webscout_data.get("network_type") if webscout_data else None
        row["ws_network_provider"] = webscout_data.get("network_provider") if webscout_data else None
        row["ws_network_service"] = webscout_data.get("network_service") if webscout_data else None
        row["ws_network_service_region"] = webscout_data.get("network_service_region") if webscout_data else None
        row["ws_network_provider_services"] = webscout_data.get("network_provider_services") if webscout_data else None
        row["ws_behavior"] = webscout_data.get("behavior") if webscout_data else None
        row["ws_as_org"] = webscout_data.get("as_org") if webscout_data else None
        row["ws_asn"] = webscout_data.get("asn") if webscout_data else None
        row["ws_desc"] = webscout_data.get("description") if webscout_data else None

    if "google_safe_browsing" in selected_engines:
        google_safe_browsing_data = result.get("google_safe_browsing", {})
        row["gsb_threat"] = google_safe_browsing_data.get("threat_found") if google_safe_browsing_data else None

    if "shodan" in selected_engines:
        shodan_data = result.get("shodan", {})
        row["shodan_ports"] = shodan_data.get("ports") if shodan_data else None

    if "phishtank" in selected_engines:
        phishtank_data = result.get("phishtank", {})
        row["phishtank_in_db"] = phishtank_data.get("in_database") if phishtank_data else None
        row["phishtank_verified"] = phishtank_data.get("verified") if phishtank_data else None
        row["phishtank_valid"] = phishtank_data.get("valid") if phishtank_data else None

    if "urlscan" in selected_engines:
        urlscan_data = result.get("urlscan", {})
        row["urlscan_count"] = urlscan_data.get("scan_count") if urlscan_data else None
        row["urlscan_top_domains"] = urlscan_data.get("top_domains") if urlscan_data else None

    if "mde" in selected_engines:
        mde_data = result.get("mde", {})
        row["mde_first_seen"] = mde_data.get("orgFirstSeen") if mde_data else None
        row["mde_last_seen"] = mde_data.get("orgLastSeen") if mde_data else None
        row["mde_org_prevalence"] = mde_data.get("orgPrevalence") if mde_data else None

    if "opencti" in selected_engines:
        opencti_data = result.get("opencti", {})
        row["opencti_entity_counts"] = opencti_data.get("entity_counts") if opencti_data else None
        row["opencti_global_count"] = opencti_data.get("global_count") if opencti_data else None
    
    if "hudsonrock" in selected_engines:
        hudsonrock_data = result.get("hudsonrock", {})
        row["hr_total_corporate_services"] = hudsonrock_data.get("total_corporate_services") if hudsonrock_data else None
        row["hr_total_user_services"] = hudsonrock_data.get("total_user_services") if hudsonrock_data else None
        row["hr_total"] = hudsonrock_data.get("total") if hudsonrock_data else None
        row["hr_total_stealers"] = hudsonrock_data.get("totalStealers") if hudsonrock_data else None
        row["hr_employees"] = hudsonrock_data.get("employees") if hudsonrock_data else None
        row["hr_users"] = hudsonrock_data.get("users") if hudsonrock_data else None
        row["hr_third_parties"] = hudsonrock_data.get("third_parties") if hudsonrock_data else None
        row["hr_stealer_families"] = hudsonrock_data.get("stealerFamilies") if hudsonrock_data else None

    if "crowdstrike" in selected_engines:
        crowdstrike_data = result.get("crowdstrike", {})
        row["cs_device_count"] = crowdstrike_data.get("device_count") if crowdstrike_data else None
        row["cs_actor"] = crowdstrike_data.get("actors") if crowdstrike_data else None
        row["cs_confidence"] = crowdstrike_data.get("malicious_confidence") if crowdstrike_data else None
        row["cs_threat_types"] = crowdstrike_data.get("threat_types") if crowdstrike_data else None
        row["cs_malwares"] = crowdstrike_data.get("malware_families") if crowdstrike_data else None
        row["cs_kill_chain"] = crowdstrike_data.get("kill_chain") if crowdstrike_data else None
        row["cs_vulns"] = crowdstrike_data.get("vulnerabilities") if crowdstrike_data else None
    
    return row

def prepare_data_for_export(analysis_results):
    """
    Prepares data for export based on the analysis results.

    Args:
        analysis_results (AnalysisResults): An object containing the results of the analysis and the selected engines.

    Returns:
        list: A list of rows, where each row is prepared based on the analysis results and selected engines.
    """
    data = []
    for result in analysis_results.results:
        row = prepare_row(result, analysis_results.selected_engines)
        data.append(row)
    return data

def export_to_csv(data, timestamp):
    """
    Exports the given data to a CSV file and sends it as an attachment.

    Args:
        data (list or dict): The data to be exported to CSV. It should be in a format that can be converted to a pandas DataFrame.
        timestamp (str): A timestamp string to be used in the CSV file name.

    Returns:
        Response: A Flask response object that sends the CSV file as an attachment.

    The CSV file is named using the provided timestamp and is deleted 10 seconds after being sent.
    """
    df = pd.DataFrame(data)
    csv_path = f'{timestamp}_analysis_result.csv'
    df.to_csv(csv_path, index=False, sep=';')
    response = send_file(csv_path, as_attachment=True)
    threading.Thread(target=lambda path: (time.sleep(10), os.remove(path)), args=(csv_path,)).start()
    return response

def export_to_excel(data, timestamp):
    """
    Exports the given data to an Excel file with a timestamp in the filename.

    Args:
        data (list of dict): The data to be exported, where each dictionary represents a row.
        timestamp (str): A string representing the timestamp to be included in the filename.

    Returns:
        Response: A Flask response object to send the file as an attachment.

    The function performs the following steps:
    1. Converts the data into a pandas DataFrame.
    2. Creates an Excel file with the given timestamp in the filename.
    3. Writes the DataFrame to the Excel file with the sheet name 'Results'.
    4. Applies auto-filter to the worksheet.
    5. Adjusts the width of each column based on the maximum length of the values in that column.
    6. Sends the file as an attachment in the response.
    7. Starts a background thread to delete the file after 10 seconds.

    Note:
        This function requires the 'pandas', 'openpyxl', 'flask', 'threading', 'time', and 'os' modules.
    """
    df = pd.DataFrame(data)
    excel_path = f'{timestamp}_analysis_result.xlsx'
    with pd.ExcelWriter(excel_path, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Results')
        workbook = writer.book
        worksheet = writer.sheets['Results']
        (max_row, max_col) = df.shape
        worksheet.auto_filter.ref = worksheet.dimensions
        for col in worksheet.columns:
            max_length = 0
            column = col[0].column_letter
            for cell in col:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = (max_length + 2)
            worksheet.column_dimensions[column].width = adjusted_width
    response = send_file(excel_path, as_attachment=True)
    threading.Thread(target=lambda path: (time.sleep(10), os.remove(path)), args=(excel_path,)).start()
    return response