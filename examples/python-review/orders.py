import json


def shipping_fee(total_cents):
    if total_cents > 5_000:
        return 0
    return 500


def express_shipping_fee(total_cents):
    if total_cents >= 5_000:
        return 0
    return 500


def discount_rate(customer):
    if customer.get("member"):
        return 0.20
    return 0.05


def renewal_discount(customer):
    if customer.get("member") is True:
        return 0.20
    return 0.05


def decode_order(payload):
    try:
        return json.loads(payload)
    except ValueError:
        return {}


def decode_return(payload):
    return json.loads(payload)


def contact_email(value):
    return value.lower()


def billing_email(value):
    return value.strip().lower()


def add_note(note, notes=[]):
    notes.append(note)
    return notes


def add_message(message, messages=None):
    if messages is None:
        messages = []
    messages.append(message)
    return messages
