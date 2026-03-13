from calculator import add_numbers, average_numbers, label_status


def test_add_numbers() -> None:
    assert add_numbers(2, 3) == 5


def test_average_numbers() -> None:
    assert average_numbers([10, 20, 30]) == 20


def test_label_status() -> None:
    assert label_status(12) == "ready"
