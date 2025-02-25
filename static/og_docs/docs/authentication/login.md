# Login

Authenticates a user and creates a session.

## Route
- `/login`

## Methods
- `GET`: Displays the login form.
- `POST`: Processes the login form.

## Example Request
```json
{
  "username": "john_doe",
  "password": "password123"
}

## Example Response
- Success: Redirects to /dashboard.
- Failure: Returns "Invalid credentials" with status code 401.