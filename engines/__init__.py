from utils.config import Secrets

from .abuseipdb import AbuseIPDBEngine
from .abusix import AbusixEngine
from .alienvault import AlienVaultEngine
from .bad_asn import BadASNEngine
from .chrome_extension import ChromeExtensionEngine
from .criminalip import CriminalIPEngine
from .crowdstrike import CrowdstrikeEngine
from .crtsh import CrtShEngine
from .dfir_iris import DFIRIrisEngine
from .github import GitHubEngine
from .google import GoogleCSEEngine
from .google_dns import GoogleDNSEngine
from .google_safe_browsing import GoogleSafeBrowsingEngine
from .hudsonrock import HudsonRockEngine
from .ioc_one import IOCOneHTMLEngine, IOCOnePDFEngine
from .ipapi import IPAPIEngine
from .ipinfo import IPInfoEngine
from .ipquery import IPQueryEngine
from .microsoft_defender_for_endpoint import MDEEngine
from .misp import MISPEngine
from .opencti import OpenCTIEngine
from .phishtank import PhishTankEngine
from .rdap import RDAPEngine
from .reverse_dns import ReverseDNSEngine
from .reversinglabs_spectra_analyze import RLAnalyzeEngine
from .shodan import ShodanEngine
from .spur_us import SpurUSEngine
from .threatfox import ThreatFoxEngine
from .urlscan import URLScanEngine
from .virustotal import VirusTotalEngine
from .webscout import WebscoutEngine


def get_engine_instances(secrets: Secrets, proxies: dict, ssl_verify: bool) -> dict:
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
        SpurUSEngine(secrets, proxies, ssl_verify),
        ThreatFoxEngine(secrets, proxies, ssl_verify),
        URLScanEngine(secrets, proxies, ssl_verify),
        WebscoutEngine(secrets, proxies, ssl_verify),
    ]

    return {engine.name: engine for engine in engines}
