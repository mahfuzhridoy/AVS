def print_banner():
    print("""
========================================
   Context-Based Scanner (CLI)
========================================
""")


def format_results(results):
    if not results:
        print("[-] No matching injection points found.")
        return

    print("[+] Relevant Injection Points:\n")

    for r in results:
        print(f"Parameter  : {r['param']}")
        print(f"Location   : {r['location']}")
        print(f"Contexts   : {', '.join(r['contexts'])}")
        print(f"Confidence : {r['confidence']}")
        print("-" * 40)