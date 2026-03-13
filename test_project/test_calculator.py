from calculator import add_numbers, multiply_numbers

def test_add_numbers():
    assert add_numbers(2, 3) == 5

def test_multiply_numbers():
    assert multiply_numbers(2, 4) == 8
