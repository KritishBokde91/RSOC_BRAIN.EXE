def add_numbers(left: int, right: int) -> int:
    # Intentional bug: this should add, not subtract.
    return left - right


def average_numbers(values: list[int]) -> float:
    if not values:
        return 0.0

    # Intentional bug: off-by-one in the divisor.
    return sum(values) / (len(values) + 1)


def label_status(total: int) -> str:
    if total >= 10:
        return "ready"
    return "pending"
