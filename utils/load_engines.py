from engines.abuseipdb import AbuseIPDBEngine
from engines.abusix import AbusixEngine
from engines.alienvault import AlienVaultEngine
from engines.bad_asn import BadASNEngine
from engines.chrome_extension import ChromeExtensionEngine
from engines.criminalip import CriminalIPEngine
from engines.crowdstrike import CrowdstrikeEngine
from engines.crtsh import CrtShEngine
from engines.dfir_iris import DFIRIrisEngine
from engines.github import GitHubEngine
from engines.google import GoogleCSEEngine
from engines.google_dns import GoogleDNSEngine
from engines.google_safe_browsing import GoogleSafeBrowsingEngine
from engines.hudsonrock import HudsonRockEngine
from engines.ioc_one import IOCOneHTMLEngine, IOCOnePDFEngine
from engines.ipapi import IPAPIEngine
from engines.ipinfo import IPInfoEngine
from engines.ipquery import IPQueryEngine
from engines.microsoft_defender_for_endpoint import MDEEngine
from engines.misp import MISPEngine
from engines.opencti import OpenCTIEngine
from engines.phishtank import PhishTankEngine
from engines.rdap import RDAPEngine
from engines.reverse_dns import ReverseDNSEngine
from engines.reversinglabs_spectra_analyze import RLAnalyzeEngine
from engines.rosti import RostiEngine
from engines.shodan import ShodanEngine
from engines.spur_us import SpurUSEngine
from engines.threatfox import ThreatFoxEngine
from engines.urlscan import URLScanEngine
from engines.virustotal import VirusTotalEngine
from engines.webscout import WebscoutEngine
from models.base_engine import BaseEngine
from utils.config import Secrets


def get_engine_instances(
    secrets: Secrets, proxies: dict, ssl_verify: bool
) -> dict[str, BaseEngine]:
    """
    Instantiates and returns a dictionary of all available engines.
    Key is the engine name (slug), Value is the engine instance.
    """
    engines = [
        AbuseIPDBEngine(secrets, proxies, ssl_verify),
        ShodanEngine(secrets, proxies, ssl_verify),
        VirusTotalEngine(secrets, proxies, ssl_verify),
        ReverseDNSEngine(secrets, proxies, ssl_verify),
        AbusixEngine(secrets, proxies, ssl_verify),
        AlienVaultEngine(secrets, proxies, ssl_verify),
        BadASNEngine(secrets, proxies, ssl_verify),
        ChromeExtensionEngine(secrets, proxies, ssl_verify),
        CriminalIPEngine(secrets, proxies, ssl_verify),
        CrowdstrikeEngine(secrets, proxies, ssl_verify),
        CrtShEngine(secrets, proxies, ssl_verify),
        DFIRIrisEngine(secrets, proxies, ssl_verify),
        GitHubEngine(secrets, proxies, ssl_verify),
        GoogleCSEEngine(secrets, proxies, ssl_verify),
        GoogleDNSEngine(secrets, proxies, ssl_verify),
        GoogleSafeBrowsingEngine(secrets, proxies, ssl_verify),
        HudsonRockEngine(secrets, proxies, ssl_verify),
        IOCOneHTMLEngine(secrets, proxies, ssl_verify),
        IOCOnePDFEngine(secrets, proxies, ssl_verify),
        IPAPIEngine(secrets, proxies, ssl_verify),
        IPInfoEngine(secrets, proxies, ssl_verify),
        IPQueryEngine(secrets, proxies, ssl_verify),
        MDEEngine(secrets, proxies, ssl_verify),
        MISPEngine(secrets, proxies, ssl_verify),
        OpenCTIEngine(secrets, proxies, ssl_verify),
        PhishTankEngine(secrets, proxies, ssl_verify),
        RDAPEngine(secrets, proxies, ssl_verify),
        RLAnalyzeEngine(secrets, proxies, ssl_verify),
        RostiEngine(secrets, proxies, ssl_verify),
        SpurUSEngine(secrets, proxies, ssl_verify),
        ThreatFoxEngine(secrets, proxies, ssl_verify),
        URLScanEngine(secrets, proxies, ssl_verify),
        WebscoutEngine(secrets, proxies, ssl_verify),
    ]

    return {engine.name: engine for engine in engines}
