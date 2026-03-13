def add_numbers(a, b):
    # intentional bug: subtracting instead of adding
    return a - b

def multiply_numbers(a, b):
    return a * b

def divide_numbers(a, b):
    # intentional bug: no guard against division by zero
    return a / b

def get_average(numbers):
    # intentional bug: off-by-one in dividing by length + 1
    total = 0
    for n in numbers:
        total += n
    return total / (len(numbers) + 1)

def process_data(data):
    result = data * 2
    return result
    # intentional bug: unreachable code after return
    print("Processing complete")

def safe_parse(value):
    try:
        return int(value)
    except:
        pass  # intentional bug: silent exception swallowing

def increment_value(x):
    # intentional bug: decrementing instead of incrementing
    return x - 1
