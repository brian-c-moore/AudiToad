def shipping_fee(order_total_cents):
    if order_total_cents > 5_000:
        return 0
    return 500
