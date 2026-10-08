"""Explicit built-in registry; third-party extensions can subclass Plugin."""

from __future__ import annotations

from shadowscan.modules.base import Plugin
from .external_plugins import discover
from shadowscan.modules.cms.cms_detector import CMSDetector
from shadowscan.modules.cms.drupal_scanner import DrupalScanner
from shadowscan.modules.cms.joomla_scanner import JoomlaScanner
from shadowscan.modules.cms.magento_scanner import MagentoScanner
from shadowscan.modules.cms.wordpress_scanner import WordPressScanner
from shadowscan.modules.cve.version_vuln_mapper import CVEMapper
from shadowscan.modules.network.ssl_tls_analyzer import TLSAnalyzer
from shadowscan.modules.network.ssh_scanner import SSHScanner
from shadowscan.modules.network.rdp_scanner import RDPScanner
from shadowscan.modules.network.ftp_scanner import FTPScanner
from shadowscan.modules.network.smtp_scanner import SMTPScanner
from shadowscan.modules.recon.dns_enum import DNSEnumerator
from shadowscan.modules.recon.host_discovery import HostDiscovery
from shadowscan.modules.recon.port_scanner import PortScanner
from shadowscan.modules.recon.udp_scanner import UDPScanner
from shadowscan.modules.recon.service_detector import ServiceDetector
from shadowscan.modules.recon.technology_detector import TechnologyDetector
from shadowscan.modules.recon.subdomain_enum import SubdomainEnumerator
from shadowscan.modules.recon.waf_detector import WAFDetector
from shadowscan.modules.web.api_scanner import APIScanner
from shadowscan.modules.web.cookie_analyzer import CookieAnalyzer
from shadowscan.modules.web.cors_scanner import CORSScanner
from shadowscan.modules.web.crawler import Crawler
from shadowscan.modules.web.csrf_scanner import CSRFScanner
from shadowscan.modules.web.directory_bruteforce import DirectoryScanner
from shadowscan.modules.web.graphql_scanner import GraphQLScanner
from shadowscan.modules.web.http_header_analyzer import HeaderAnalyzer
from shadowscan.modules.web.parameter_discovery import ParameterDiscovery
from shadowscan.modules.web.file_upload_scanner import FileUploadScanner
from shadowscan.modules.web.jwt_analyzer import JWTAnalyzer
from shadowscan.modules.web.lfi_rfi_scanner import TraversalScanner
from shadowscan.modules.web.open_redirect import OpenRedirectScanner
from shadowscan.modules.web.sqli_scanner import SQLiScanner
from shadowscan.modules.web.ssti_scanner import SSTIScanner
from shadowscan.modules.web.xss_scanner import XSSScanner
from shadowscan.modules.web.websocket_scanner import WebSocketScanner

PLUGINS: dict[str, type[Plugin]] = {
    cls.name: cls
    for cls in (
        PortScanner,
        UDPScanner,
        SubdomainEnumerator,
        TLSAnalyzer,
        HostDiscovery,
        DNSEnumerator,
        ServiceDetector,
        TechnologyDetector,
        WAFDetector,
        CookieAnalyzer,
        CORSScanner,
        Crawler,
        CSRFScanner,
        HeaderAnalyzer,
        OpenRedirectScanner,
        SQLiScanner,
        SSTIScanner,
        XSSScanner,
        APIScanner,
        GraphQLScanner,
        DirectoryScanner,
        CMSDetector,
        WordPressScanner,
        JoomlaScanner,
        DrupalScanner,
        MagentoScanner,
        CVEMapper,
        ParameterDiscovery,
        FileUploadScanner,
        JWTAnalyzer,
        SSHScanner,
        RDPScanner,
        FTPScanner,
        SMTPScanner,
        WebSocketScanner,
        TraversalScanner,
    )
}
PROFILES = {
    "quick": ("headers", "cookies", "technology", "cms", "waf", "parameters"),
    "standard": (
        "headers",
        "cookies",
        "technology",
        "cms",
        "waf",
        "tls",
        "cors",
        "csrf",
        "xss",
        "sqli",
        "ssti",
        "open_redirect",
        "crawler",
        "ports",
        "api",
        "graphql",
        "directories",
        "cve",
        "parameters",
        "file_upload",
        "jwt",
        "traversal",
    ),
    "full": tuple(PLUGINS),
    "web": tuple(k for k, v in PLUGINS.items() if v.group in {"web", "cms"}),
    "network": tuple(k for k, v in PLUGINS.items() if v.group in {"network", "recon"}),
    "recon": tuple(k for k, v in PLUGINS.items() if v.group == "recon"),
}


def select_plugins(
    profile: str,
    modules: list[str] | None = None,
    disabled: list[str] | None = None,
    mode: str = "active",
    external: bool = False,
) -> list[Plugin]:
    """Resolve names without importing arbitrary user-supplied modules."""
    from .errors import ConfigurationError

    if profile not in PROFILES:
        raise ConfigurationError(f"Unknown profile: {profile}")
    registry = {**PLUGINS, **discover(set(PLUGINS))} if external else PLUGINS
    names = modules if modules is not None else list(PROFILES[profile])
    unknown = set(names) - set(registry)
    if unknown:
        raise ConfigurationError(f"Unknown modules: {', '.join(sorted(unknown))}")
    disabled = disabled or []
    return [
        registry[name]()
        for name in dict.fromkeys(names)
        if name not in disabled and (mode != "passive" or not registry[name].active)
    ]
