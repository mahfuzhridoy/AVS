import argparse
from injection_detector import InjectionDetector
from utils import print_banner, format_results
from selector import select_bug, select_context
from engine_loader import EngineLoader
import questionary


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Context-Based Scanner")
    parser.add_argument("--payload-file", help="Custom payload file")
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-l", "--list", help="File with URLs")
    args = parser.parse_args()

    if not args.url and not args.list:
        print("[-] Provide -u or -l")
        return

    # selecting context
    bug = select_bug()
    if not bug:
        return

    context = select_context(bug)
    if not context:
        return

    print(f"\n[+] Selected Bug: {bug}")
    print(f"[+] Selected Context: {context}\n")

    # url loading
    urls = []

    if args.list:
        with open(args.list, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        urls = [args.url]

    detector = InjectionDetector()

    # scanning loop
    for url in urls:
        print(f"\n[+] Scanning: {url}")

        results = detector.detect(url=url)

        # filter results
        filtered = filter_by_context(results, bug, context)

        format_results(filtered)

        if not filtered:
            continue

        # ask user
        run_payload = questionary.confirm(
            "Do you want to run payload injection on these points?"
        ).ask()

        if not run_payload:
            continue

        # load engine
        engine = EngineLoader(
            bug,
            payload_file=args.payload_file
        ).load()

        if not engine:
            print("[-] No engine available for this bug yet.")
            continue

        print("[*] Running payload engine...\n")

        payload_results = engine.run(url, filtered)

        if not payload_results:
            print("[-] No payload reflections found.")
        else:
            for r in payload_results:
                print(f"[XSS] {r['url']}")
                print(f"Param: {r['param']}")
                print(f"Payload: {r['payload']}")
                print("-" * 40)


def filter_by_context(results, bug, context):
    filtered = []

    for r in results:
        ctx = r["contexts"]

        # XSS
        if bug == "xss":
            if context == "reflected" and ("html" in ctx or "attribute" in ctx):
                filtered.append(r)

            elif context == "dom" and "js" in ctx:
                filtered.append(r)

            elif context == "stored":
                filtered.append(r)

        # SSRF
        elif bug == "ssrf":
            if "url" in ctx:
                filtered.append(r)

        # IDOR
        elif bug == "idor":
            if r["location"] in ["query", "body"]:
                filtered.append(r)

    return filtered


if __name__ == "__main__":
    main()
