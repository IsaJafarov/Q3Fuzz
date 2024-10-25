import random

def custom_random():
    # Define the probability weights for each range
    ranges = [
        (1, 100, 0.1),        # 10% chance of choosing below 100
        (100, 10000, 0.8),    # 80% chance of choosing between 100 and 10000
        (10000, 100000, 0.1)  # 10% chance of choosing above 10000
    ]
    
    # Randomly select a range based on weights
    selected_range = random.choices(ranges, weights=[r[2] for r in ranges])[0]
    
    # Choose a random number within the selected range
    return random.randint(selected_range[0], selected_range[1])

# Generate a random number with the custom distribution
random_value = custom_random()
print(random_value)