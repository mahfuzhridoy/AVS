import questionary
from questionary import Choice

def select_bug():
    return questionary.select(
        "Select the bug you want to scan for:",
        choices=[
            Choice("XSS", value="xss"),
            Choice("SSRF", value="ssrf"),
            Choice("IDOR", value="idor"),
        ]
    ).ask()


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

    return questionary.select(
        f"Select context for {bug.upper()}:",
        choices=context_map.get(bug, [])
    ).ask()