"""OSINT and intelligence gathering routes."""
import logging

from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)
osint_bp = Blueprint('osint', __name__)

from tools.osint.passive_recon import shodan_search, whois_lookup, the_harvester, dnsdumpster_recon, censys_search
from tools.osint.social_intel import sherlock_search, holehe_check, breach_lookup
from tools.osint.threat_intel import virustotal_lookup, otx_lookup, urlscan_lookup, shodan_cve_lookup


@osint_bp.route('/api/osint/passive-recon', methods=['POST'])
def osint_passive_recon():
    """Comprehensive passive recon: subdomains, emails, DNS, hosts."""
    params = request.json or {}
    domain = params.get('domain', '')
    if not domain:
        return jsonify({"success": False, "error": "domain is required"}), 400
    try:
        sources = params.get('sources', 'all')
        results = {
            'harvester': the_harvester(domain, sources),
            'whois': whois_lookup(domain),
            'dns': dnsdumpster_recon(domain),
        }
        if params.get('shodan_key'):
            results['shodan'] = shodan_search(domain, params['shodan_key'])
        return jsonify({"success": True, "domain": domain, "results": results})
    except Exception as e:
        logger.error(f"Passive recon error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@osint_bp.route('/api/osint/threat-intel', methods=['POST'])
def osint_threat_intel():
    """Threat intelligence IOC lookup (VT, OTX, URLScan)."""
    params = request.json or {}
    ioc = params.get('ioc', '')
    if not ioc:
        return jsonify({"success": False, "error": "ioc is required"}), 400
    try:
        results = {
            'urlscan': urlscan_lookup(ioc),
            'otx': otx_lookup(ioc, params.get('otx_key', '')),
        }
        if params.get('vt_key'):
            results['virustotal'] = virustotal_lookup(ioc, params['vt_key'])
        return jsonify({"success": True, "ioc": ioc, "results": results})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@osint_bp.route('/api/osint/social-recon', methods=['POST'])
def osint_social_recon():
    """Social media and identity OSINT."""
    params = request.json or {}
    try:
        results = {}
        if params.get('username'):
            results['sherlock'] = sherlock_search(params['username'])
        if params.get('email'):
            results['holehe'] = holehe_check(params['email'])
        return jsonify({"success": True, "results": results})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@osint_bp.route('/api/osint/breach-check', methods=['POST'])
def osint_breach_check():
    """Check email against known breach databases."""
    params = request.json or {}
    email = params.get('email', '')
    if not email:
        return jsonify({"success": False, "error": "email is required"}), 400
    try:
        result = breach_lookup(email)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@osint_bp.route('/api/osint/shodan', methods=['POST'])
def osint_shodan():
    """Shodan search and host lookup."""
    params = request.json or {}
    try:
        result = shodan_search(params.get('query', ''), params.get('api_key', ''))
        return jsonify({"success": True, "result": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@osint_bp.route('/api/osint/ioc-cve', methods=['POST'])
def osint_cve_lookup():
    """Look up CVEs for services on an IP via Shodan."""
    params = request.json or {}
    try:
        result = shodan_cve_lookup(params.get('ip', ''))
        return jsonify({"success": True, "result": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
