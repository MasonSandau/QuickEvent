# Attendee Model

Represents an attendee for an event.

## Attributes
- `id` (str): Primary key, unique identifier for the attendee (UUID as string).
- `event_id` (str): Foreign key linking the attendee to an event.
- `active_name` (str): Active name of the attendee (max 150 characters).
- `first_name` (str): First name of the attendee (max 150 characters).
- `last_name` (str): Last name of the attendee (max 150 characters).
- `invite_code` (str): Unique invite code for the attendee (UUID as string).
- `qr_code_generated` (bool): Indicates whether a QR code has been generated for the attendee.

## Relationships
- `event`: Many-to-one relationship with the Event model.

## Example Usage
```python
# Create a new attendee
new_attendee = Attendee(
    id="123e4567-e89b-12d3-a456-426614174000",
    event_id="550e8400-e29b-41d4-a716-446655440000",
    active_name="Tech Enthusiast",
    first_name="Jane",
    last_name="Doe",
    invite_code="550e8400-e29b-41d4-a716-446655440001",
    qr_code_generated=False
)
db.session.add(new_attendee)
db.session.commit()