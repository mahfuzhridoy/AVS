import questionary
from questionary import Choice

def select_bug():
    bug = questionary.select(
        "Select the bug you want to scan for:",
        choices=[
            Choice("XSS", value="xss"),
            Choice("SSRF", value="ssrf"),
            Choice("IDOR", value="idor"),
        ]
    ).ask() #waits for user to select an option after executing the prompt.

    return bug  #Returns the selected value to the function who call it by name "bug"


def select_context(bug):
    context_map = {
        "xss": [
            Choice("Reflected XSS", value="reflected"),
            Choice("Stored XSS", value="stored"),
            Choice("DOM-based XSS", value="dom"),
        ],
        "ssrf": [
            Choice("URL parameter injection", value="url_param"),
            Choice("Webhook interaction", value="webhook"),
            Choice("File fetch functionality", value="file_fetch"),
        ],
        "idor": [
            Choice("User ID parameter", value="user_id"),
            Choice("Order/Transaction ID", value="order_id"),
            Choice("File/resource access", value="file_access"),
        ]
    }

    context = questionary.select(
        f"Select context for {bug.upper()}:",
        choices=context_map.get(bug, [])
    ).ask()

    return context


def main():
    bug = select_bug()

    if not bug:
        print("No bug selected. Exiting.")
        return

    context = select_context(bug)

    if not context:
        print("No context selected. Exiting.")
        return

    print("\n--- Selection Summary ---")
    print(f"Bug: {bug}")
    print(f"Context: {context}")


if __name__ == "__main__":
    main()