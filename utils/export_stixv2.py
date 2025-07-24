import json
import datetime
import uuid
import sys
import requests
from typing import Dict, List, Optional, Any
import logging
from pathlib import Path
from flask import Response
from flask import jsonify
from pathlib import Path
import threading
import time
from flask import send_file

from stix2 import (
    Bundle,
    Identity,
    Indicator,
    Relationship,
    IPv4Address,
    URL,
    DomainName,
    File,
    Software,
    Malware,
    ThreatActor,
    TLP_WHITE,
)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Define constants
MIN_VT_MALICIOUS_COUNT = 10
OBSERVABLE_TYPE_MAPPING = {
    "IPv4": lambda value: IPv4Address(value=value, object_marking_refs=[TLP_WHITE]),
    "FQDN": lambda value: DomainName(value=value, object_marking_refs=[TLP_WHITE]),
    "URL": lambda value: URL(value=value, object_marking_refs=[TLP_WHITE]),
    "MD5": lambda value: File(hashes={"md5": value}, object_marking_refs=[TLP_WHITE]),
    "SHA1": lambda value: File(hashes={"sha1": value}, object_marking_refs=[TLP_WHITE]),
    "SHA256": lambda value: File(hashes={"sha256": value}, object_marking_refs=[TLP_WHITE]),
    "CHROME_EXTENSION": lambda value: Software(name=value, object_marking_refs=[TLP_WHITE]),
}

PATTERN_MAPPING = {
    "IPv4": lambda value: f"[ipv4-addr:value = '{value}']",
    "FQDN": lambda value: f"[domain-name:value = '{value}']",
    "URL": lambda value: f"[url:value = '{value}']",
    "MD5": lambda value: f"[file:hashes.md5 = '{value}']",
    "SHA1": lambda value: f"[file:hashes.sha1 = '{value}']",
    "SHA256": lambda value: f"[file:hashes.sha256 = '{value}']",
    "CHROME_EXTENSION": lambda value: f"[software:name = '{value}']",
}


def get_type_from_observable(obs_type: str, value: str):
    """Convert observable type to STIX object"""
    converter = OBSERVABLE_TYPE_MAPPING.get(obs_type)
    if converter:
        try:
            return converter(value)
        except Exception as e:
            logger.error(f"Error creating observable for {obs_type}:{value} - {str(e)}")
    return None


def build_external_references(item: Dict[str, Any]) -> List[Dict[str, str]]:
    """Build external references from item data"""
    external_references = []

    # Add VirusTotal references
    try:
        vt = item.get("virustotal")
        if vt is not None and isinstance(vt, dict):
            # Ignore VirusTotal data if malicious count is undetected
            if vt.get("total_malicious") > 0:
                if vt_link := vt.get("link"):
                    external_references.append(
                        {
                            "source_name": "VirusTotal",
                            "url": vt_link,
                            "description": f"{vt.get('detection_ratio', 'Unknown')} detections on VirusTotal",
                        }
                    )
    except Exception as e:
        logger.error(f"Failed to retrieve VirusTotal data: {str(e)}")

    # Add AlienVault references
    try:
        av = item.get("alienvault")
        if av is not None and isinstance(av, dict):
            # Add AlienVault pulses
            if pulses := av.get("pulses"):
                for pulse in pulses:
                    if "title" in pulse and "url" in pulse:
                        url = pulse["url"]
                        if url and isinstance(url, str) and url.startswith(("http://", "https://")):
                            external_references.append(
                                {
                                    "source_name": "AlienVault Pulse",
                                    "url": url,
                                    "description": pulse.get("title", ""),
                                }
                            )
    except Exception as e:
        logger.error(f"Failed to retrieve AlienVault data: {str(e)}")

    # Add GitHub references
    try:
        gh = item.get("github")
        if gh is not None and isinstance(gh, dict) and "results" in gh:
            gh = item.get("github", {}).get("results", [])
            for repo in gh:
                if "title" in repo and "url" in repo:
                    external_references.append(
                        {
                            "source_name": "GitHub Repository",
                            "url": repo["url"],
                            "description": f"Observed in {repo.get('title', '')} Github Repo",
                        }
                    )
    except Exception as e:
        logger.error(f"Failed to retrieve GitHub data: {str(e)}")

    # Add extension references
    try:
        if ext := item.get("extension"):
            external_references.append(
                {
                    "source_name": "Browser Extension",
                    "url": ext["url"],
                    "description": f"Browser Extension: {ext.get('name', 'Unknown')}",
                }
            )
    except Exception as e:
        logger.error(f"Failed to retrieve extension data: {str(e)}")

    return external_references if external_references else None


def create_stix_bundle(
    data: List[Dict[str, Any]], specified_indicators: List[str], specified_labels: List[str]
) -> Bundle:
    """Create a STIX bundle from the provided data"""
    identity = Identity(
        id=f"identity--{uuid.uuid4()}",
        name="Cyberbro",
        identity_class="organization",
        description="Cyberbro is an Open Source IoC enrichment tool",
        contact_information="https://github.com/standfrbd/cyberbro",
        object_marking_refs=[TLP_WHITE],
    )

    objects = [identity]
    valid_indicators_count = 0

    for item in data:
        observable = item.get("observable")
        obs_type = item.get("type")

        if not observable or not obs_type:
            logger.warning(f"Skipping item missing observable or type: {item}")
            continue

        # Create the cyber observable
        cyber_observable = get_type_from_observable(obs_type, observable)
        if not cyber_observable:
            logger.warning(f"Could not create observable for type {obs_type}: {observable}")
            continue

        objects.append(cyber_observable)

        # Build external references
        external_references = build_external_references(item)

        if observable not in specified_indicators:
            logger.info(f"Skipping indicator for {obs_type}:{observable} - not in specified indicators")
            continue

        # Prepare indicator data
        indicator_id = f"indicator--{uuid.uuid4()}"
        pattern_func = PATTERN_MAPPING.get(obs_type)
        if not pattern_func:
            logger.warning(f"No pattern mapping for {obs_type}")
            continue

        pattern = pattern_func(observable)

        # Ensure 'cyberbro' label is always included
        if specified_labels:
            labels = specified_labels.copy()
            if "cyberbro" not in labels:
                labels.append("cyberbro")
        else:
            labels = ["cyberbro"]

        # Create indicator
        indicator = Indicator(
            id=indicator_id,
            labels=labels,
            pattern=pattern,
            pattern_type="stix",
            valid_from=datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            created_by_ref=identity.id,
            external_references=external_references,
            description=f"Indicator for {obs_type}: {observable}",
        )
        objects.append(indicator)
        valid_indicators_count += 1

        # Create relationship between indicator and observable
        relationship = Relationship(
            id=f"relationship--{uuid.uuid4()}",
            relationship_type="based-on",
            source_ref=indicator.id,
            target_ref=cyber_observable.id,
        )
        objects.append(relationship)

        # Process threat actors
        alienvault = item.get("alienvault")
        if alienvault is not None and isinstance(alienvault, dict):
            if adversaries := alienvault.get("adversary", []):
                for adversary in adversaries:
                    actor = ThreatActor(id=f"threat-actor--{uuid.uuid4()}", name=adversary, labels=["threat-actor"])
                    objects.append(actor)

                    # Relate actor to indicator
                    actor_rel = Relationship(
                        id=f"relationship--{uuid.uuid4()}",
                        relationship_type="indicates",
                        source_ref=indicator.id,
                        target_ref=actor.id,
                    )
                    objects.append(actor_rel)

            # Process malware families
            if malware_families := item.get("alienvault", {}).get("malware_families", []):
                for malware_family in malware_families:
                    malware_obj = Malware(
                        id=f"malware--{uuid.uuid4()}", name=malware_family, is_family=True, labels=["malware"]
                    )
                    objects.append(malware_obj)

                    # Relate malware to indicator
                    malware_rel = Relationship(
                        id=f"relationship--{uuid.uuid4()}",
                        relationship_type="indicates",
                        source_ref=indicator.id,
                        target_ref=malware_obj.id,
                    )
                    objects.append(malware_rel)

    logger.info(f"Created bundle with {len(objects)} STIX objects including {valid_indicators_count} indicators")
    return Bundle(objects=objects)


def export_to_stixv2(
    data, specified_indicators: Optional[List[str]] = None, specified_labels: Optional[List[str]] = None
) -> Response:
    """Export the analysis results to STIX v2 format."""
    try:
        stix_bundle = create_stix_bundle(
            data, specified_indicators=specified_indicators, specified_labels=specified_labels
        )
        stix_json = stix_bundle.serialize(pretty=True)

        # Prepare the response with proper headers for JSON download
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H_%M_%S")
        filename = f"stix_export_{timestamp}.json"

        # Write the file to disk temporarily
        temp_file_path = Path(f"{filename}")
        with open(temp_file_path, "w") as f:
            f.write(stix_json)

        threading.Thread(target=lambda path: (time.sleep(10), Path(path).unlink()), args=(temp_file_path,)).start()
        # Return the file from disk
        return send_file(
            str(temp_file_path),
            as_attachment=True,
        )
    except Exception as e:
        logger.error(f"Error exporting to STIX v2: {str(e)}")
        return jsonify({"error": f"Failed to export to STIX v2: {str(e)}"}), 500
