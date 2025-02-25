# Registration Key Model

Represents a registration key in the system.

## Attributes
- `id` (int): Primary key, unique identifier for the registration key.
- `hashed_key` (str): Hashed value of the registration key (max 255 characters).
- `role` (str): Role associated with the registration key (e.g., 'admin', 'user').
- `used` (bool): Indicates whether the registration key has been used.

## Example Usage
```python
# Create a new registration key
new_regkey = regkey(
    hashed_key="hashed_key_123",
    role="admin",
    used=False
)
db.session.add(new_regkey)
db.session.commit()