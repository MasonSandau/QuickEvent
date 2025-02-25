# User Model

Represents a user in the system.

## Attributes
- `id` (int): Primary key, unique identifier for the user.
- `username` (str): Unique username for the user (max 150 characters).
- `password` (str): Hashed password for the user (max 255 characters).
- `role` (str): Role of the user (e.g., 'admin', 'user').

## Example Usage
```python
# Create a new user
new_user = User(username="john_doe", password="hashed_password_123", role="user")
db.session.add(new_user)
db.session.commit()