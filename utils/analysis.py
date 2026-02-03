import inspect
import queue
import threading
import time
from typing import Any

from flask import Flask

from models.analysis_result import AnalysisResult
from models.base_engine import BaseEngine
from utils.config import Secrets, get_config
from utils.database import get_analysis_result, save_analysis_result

# --- NEW DYNAMIC ENGINE IMPORTS ---
from utils.load_engines import get_engine_instances
from utils.utils import is_bogon

# ----------------------------------

# Read the secrets from the config file
secrets: Secrets = get_config()

PROXIES: dict[str, str] = {"http": secrets.proxy_url, "https": secrets.proxy_url}

SSL_VERIFY: bool = secrets.ssl_verify

# Initialize ALL engine instances once on startup
LOADED_ENGINES: dict[str, BaseEngine] = get_engine_instances(secrets, PROXIES, SSL_VERIFY)


def perform_analysis(app: Flask, observables, selected_engines: list[str], analysis_id: str):
    # Normalize legacy engine names for backward compatibility
    engine_aliases = {"rdap": "rdap_whois"}
    selected_engines = [engine_aliases.get(name, name) for name in selected_engines]

    with app.app_context():
        start_time = time.time()

        # Store analysis metadata in the database
        analysis_result = AnalysisResult(
            id=analysis_id,
            results=[],
            start_time=start_time,
            end_time=None,
            start_time_string=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time)),
            end_time_string="",
            analysis_duration_string="",
            analysis_duration=0,
            selected_engines=selected_engines,
            in_progress=True,
        )
        save_analysis_result(analysis_result)

        result_queue = queue.Queue()
        threads = [
            threading.Thread(
                target=analyze_observable,
                args=(observable, index, selected_engines, result_queue),
            )
            for index, observable in enumerate(observables)
        ]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        results = collect_results_from_queue(result_queue, len(observables))
        update_analysis_metadata(analysis_id, start_time, selected_engines, results)


def analyze_observable(
    observable: dict[str, Any], index: int, selected_engines: list[str], result_queue
):
    result = {
        "observable": observable["value"],
        "type": observable["type"],
        "reversed_success": False,
    }

    # 1. Global check: Bogon
    if observable["type"] in ["IPv4", "IPv6"] and is_bogon(observable["value"]):
        observable["type"] = "BOGON"

    # Identify and filter requested engine instances
    active_instances: list[BaseEngine] = []
    for name in selected_engines:
        if name in LOADED_ENGINES:
            active_instances.append(LOADED_ENGINES[name])

    # 1.5. Special handler: Chrome Extension (always runs if type matches)
    if observable["type"] == "CHROME_EXTENSION":
        engine = LOADED_ENGINES.get("chrome_extension")
        if engine:
            # Note: The original logic uses "extension" as the key, overriding the engine's name
            result["extension"] = engine.analyze(observable["value"], observable["type"])

    # 2. Phase 1: Pre-Pivot Engines (Standard lookups that don't need reverse DNS result)
    for engine in active_instances:
        if (
            not engine.execute_after_reverse_dns
            and not engine.is_pivot_engine
            and engine.name != "chrome_extension"
        ):
            run_engine(engine, observable, result)

    # 3. Phase 2: Pivot (Reverse DNS)
    # The pivot engine runs and can modify the observable in place
    # (observable["type"]/observable["value"])
    pivot_engines: list[BaseEngine] = [
        e for e in active_instances if e.is_pivot_engine and e.name == "reverse_dns"
    ]
    for engine in pivot_engines:
        analysis_data = run_engine(engine, observable, result)

        # Specific Pivot Logic for Reverse DNS
        if analysis_data:
            result["reversed_success"] = True
            reverse_dns_results = analysis_data.get("reverse_dns")

            # Check if auto-pivoting should occur
            if reverse_dns_results and observable["type"] in ["FQDN", "URL"]:
                # Pivot: change observable type to IPv4 and use the first IP found.
                observable["type"] = "IPv4"
                observable["value"] = reverse_dns_results[0]

    # 4. Phase 3: Post-Pivot Engines (IP-only engines that benefit from pivot)
    # Run all engines except those that depend on other engine results
    for engine in active_instances:
        if (
            engine.execute_after_reverse_dns
            and not engine.is_pivot_engine
            and engine.name != "chrome_extension"
            and engine.name != "bad_asn"
        ):
            run_engine(engine, observable, result)

    # 5. Phase 4: Dependent Engines (engines that need results from other engines)
    # Run bad_asn last so it can access ASN data from ipapi, ipinfo, etc.
    for engine in active_instances:
        if engine.name == "bad_asn":
            run_engine(engine, observable, result)

    result_queue.put((index, result))


def run_engine(engine: BaseEngine, observable: dict[str, Any], result_dict):
    """Helper to run a single engine instance and store its result."""
    if observable["type"] in engine.supported_types:
        # Check if engine's analyze method accepts a context parameter
        # (e.g., bad_asn engine needs access to results from other engines)
        sig = inspect.signature(engine.analyze)
        data = (
            engine.analyze(observable["value"], observable["type"], context=result_dict)
            if "context" in sig.parameters
            else engine.analyze(observable["value"], observable["type"])
        )
        result_dict[engine.name] = data
        return data
    return None


def collect_results_from_queue(result_queue, num_observables):
    results = [None] * num_observables
    while not result_queue.empty():
        index, result = result_queue.get()
        results[index] = result
    return results


def check_analysis_in_progress(analysis_id):
    analysis_result = get_analysis_result(analysis_id)
    return analysis_result.in_progress if analysis_result else False


def update_analysis_metadata(analysis_id, start_time, selected_engines, results):
    analysis_result = get_analysis_result(analysis_id)
    if analysis_result:
        end_time = time.time()
        analysis_result.end_time = end_time
        analysis_result.end_time_string = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(end_time)
        )
        analysis_result.analysis_duration = end_time - start_time
        analysis_result.analysis_duration_string = (
            f"{int((end_time - start_time) // 60)} minutes, "
            f"{(end_time - start_time) % 60:.2f} seconds"
        )
        analysis_result.results = results
        analysis_result.in_progress = False
        save_analysis_result(analysis_result)
