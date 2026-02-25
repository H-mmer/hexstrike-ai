"""Wireless security tool routes Blueprint."""
import logging

from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)
wireless_bp = Blueprint('wireless', __name__)

# ---------------------------------------------------------------------------
# Optional tool imports — wifi_tools
# ---------------------------------------------------------------------------

try:
    from tools.wireless.wifi_tools import wifite2_attack
    _WIFI_AVAILABLE = True
except ImportError:
    _WIFI_AVAILABLE = False

    def wifite2_attack(interface, **kwargs):
        return {"success": False, "error": "wifi_tools not available"}


# ---------------------------------------------------------------------------
# Optional tool imports — bluetooth_tools
# ---------------------------------------------------------------------------

try:
    from tools.wireless.bluetooth_tools import bluez_scan, blueborne_scanner
    _BT_AVAILABLE = True
except ImportError:
    _BT_AVAILABLE = False

    def bluez_scan(**kwargs):
        return {"success": False, "error": "bluetooth_tools not available"}

    def blueborne_scanner(target_addr, **kwargs):
        return {"success": False, "error": "bluetooth_tools not available"}


# ---------------------------------------------------------------------------
# Optional tool imports — rf_tools
# ---------------------------------------------------------------------------

try:
    from tools.wireless.rf_tools import rtl_sdr_scan, hackrf_sweep
    _RF_AVAILABLE = True
except ImportError:
    _RF_AVAILABLE = False

    def rtl_sdr_scan(**kwargs):
        return {"success": False, "error": "rf_tools not available"}

    def hackrf_sweep(**kwargs):
        return {"success": False, "error": "rf_tools not available"}


# ---------------------------------------------------------------------------
# WiFi attack
# ---------------------------------------------------------------------------

@wireless_bp.route('/api/tools/wireless/wifi-attack', methods=['POST'])
def wifi_attack():
    """WiFi security testing using wifite2."""
    params = request.json or {}
    interface = params.get('interface', '')
    if not interface:
        return jsonify({"success": False, "error": "interface is required"}), 400
    target_bssid = params.get('target_bssid', None)
    attack_type = params.get('attack_type', 'all')
    try:
        result = wifite2_attack(interface, target_ssid=target_bssid, attack_type=attack_type)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"WiFi attack error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# ---------------------------------------------------------------------------
# Bluetooth scan
# ---------------------------------------------------------------------------

@wireless_bp.route('/api/tools/wireless/bluetooth-scan', methods=['POST'])
def bluetooth_scan():
    """Bluetooth device scanning and vulnerability assessment."""
    params = request.json or {}
    # interface param accepted but bluez_scan takes no args
    try:
        results = {
            'bluez': bluez_scan(),
        }
        return jsonify({"success": True, "results": results})
    except Exception as e:
        logger.error(f"Bluetooth scan error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# ---------------------------------------------------------------------------
# RF analysis
# ---------------------------------------------------------------------------

@wireless_bp.route('/api/tools/wireless/rf', methods=['POST'])
def rf_analysis():
    """RF signal analysis using RTL-SDR or HackRF."""
    params = request.json or {}
    frequency = params.get('frequency', 100.0)
    device = params.get('device', 'rtlsdr')
    try:
        if device == 'hackrf':
            result = hackrf_sweep()
        else:
            result = rtl_sdr_scan(frequency=float(frequency) * 1e6)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"RF analysis error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
