import pytest
from calculator import add_numbers, multiply_numbers, divide_numbers, get_average, increment_value

def test_add_numbers():
    assert add_numbers(2, 3) == 5, "2 + 3 should equal 5"

def test_add_negative():
    assert add_numbers(-1, 1) == 0, "-1 + 1 should equal 0"

def test_multiply_numbers():
    assert multiply_numbers(3, 4) == 12, "3 * 4 should equal 12"

def test_divide_numbers():
    assert divide_numbers(10, 2) == 5, "10 / 2 should equal 5"

def test_divide_by_zero():
    with pytest.raises(ZeroDivisionError):
        divide_numbers(10, 0)

def test_get_average():
    assert get_average([10, 20, 30]) == 20, "Average of [10, 20, 30] should be 20"

def test_increment_value():
    assert increment_value(5) == 6, "increment(5) should equal 6"
