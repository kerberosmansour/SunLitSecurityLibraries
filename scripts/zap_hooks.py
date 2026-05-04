# ZAP hook script for SunLit Security Libraries DAST scans.
# Disables heavy/crash-prone scanners before the active scan starts.


def zap_started(zap, target):
    """Called after ZAP has started — disable DOM-based XSS scanner (40026).

    The DOM XSS scanner launches a headless browser and can OOM/crash
    the ZAP container.  Disabling it here prevents the scanner from
    running at all (the rules-file IGNORE only suppresses the alert).
    """
    zap.ascan.disable_scanners("40026")
