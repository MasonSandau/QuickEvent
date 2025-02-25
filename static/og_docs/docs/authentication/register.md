# Register

Registers a new user.

## Route
- `/register`

## Methods
- `GET`: Displays the registration form.
- `POST`: Processes the registration form.

## Example Request
```json
{
  "username": "jane_doe",
  "password": "password123",
  "role": "user",
  "registration_key": "hashed_key_123"
}

## Example Response
- Success: Redirects to /dashboard.
- Failure: Returns an error message with status code 400.