import time
import subprocess
import argparse
from zapv2 import ZAPv2


def wait_for_start(zap, timeout=60):
    for _ in range(timeout):
        try:
            # This will throw if ZAP hasn't started yet
            zap.core.version
            return True
        except Exception:
            time.sleep(1)
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Run OWASP ZAP active scan and report injection alerts.")
    parser.add_argument("target", help="Target URL to scan")
    parser.add_argument(
        "--zap-path",
        default="zap.sh",
        help="Path to the ZAP executable (default: zap.sh)")
    parser.add_argument(
        "--port", type=int, default=8090, help="Port for ZAP proxy")
    args = parser.parse_args()

    zap_proc = subprocess.Popen(
        [args.zap_path, "-daemon", f"-port={args.port}",
         "-config", "api.disablekey=true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    proxies = {
        "http": f"http://localhost:{args.port}",
        "https": f"http://localhost:{args.port}",
    }
    zap = ZAPv2(proxies=proxies)

    if not wait_for_start(zap):
        print("ZAP failed to start")
        return 1

    print(f"Spidering {args.target} ...")
    zap.urlopen(args.target)
    time.sleep(2)
    zap.spider.scan(args.target)
    while int(zap.spider.status()) < 100:
        time.sleep(1)

    print("Scanning...")
    zap.ascan.scan(args.target)
    while int(zap.ascan.status()) < 100:
        time.sleep(1)

    alerts = zap.core.alerts(baseurl=args.target)
    injection_alerts = [
        a for a in alerts
        if a.get("alert") in [
            "Cross Site Scripting (Reflected)",
            "SQL Injection",
            "Command Injection"]
    ]

    for alert in injection_alerts:
        print(f"[{alert['risk']}] {alert['alert']} -> {alert['url']}")

    zap.core.shutdown()
    zap_proc.terminate()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
