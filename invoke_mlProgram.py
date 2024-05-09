import random

# Function to generate a synthetic HTML form with random attributes
def generate_synthetic_form():
    form = "<form"
    # Randomly choose form attributes (action, method)
    action = f'action="/submit_form"'
    method = f'method="{random.choice(["get", "post"])}"'
    form += f" {action} {method}>"
    # Generate random input fields
    num_inputs = random.randint(1, 5)
    for i in range(num_inputs):
        input_type = random.choice(["text", "password", "email", "number"])
        input_name = f'name="input_{i}"'
        form += f'<input type="{input_type}" {input_name}>'
    form += "</form>"
    return form

# Function to simulate HTTP response for a given form
def simulate_http_response(form):
    # Simulate server response based on the presence of SQL injection vulnerabilities
    if random.random() < 0.5:
        # If vulnerable, include SQL error message in the response
        response_content = "<html><body>Error: quoted string not properly terminated</body></html>"
    else:
        # If not vulnerable, include generic success message
        response_content = "<html><body>Form submitted successfully</body></html>"
    return response_content

# Generate synthetic HTML forms and simulate HTTP responses
def generate_training_data(num_samples):
    training_data = []
    for _ in range(num_samples):
        # Generate synthetic HTML form
        html_form = generate_synthetic_form()
        # Simulate HTTP response for the form
        http_response = simulate_http_response(html_form)
        # Add form and response pair to training data
        training_data.append((html_form, http_response))
    return training_data

if __name__ == "__main__":
    # Number of synthetic samples to generate
    num_samples = 1000
    # Generate training data
    training_data = generate_training_data(num_samples)
    # Save training data to a file (e.g., CSV)
    with open("training_data.csv", "w") as file:
        for form, response in training_data:
            file.write(f"{form},{response}\n")
    print(f"Generated {num_samples} synthetic HTML forms and simulated HTTP responses.")
