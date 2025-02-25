# Event Model

Represents an event in the system.

## Attributes
- `id` (str): Primary key, unique identifier for the event (UUID as string).
- `name` (str): Name of the event (max 150 characters).
- `date` (str): Date of the event (formatted as a string).
- `theme` (str): Theme of the event (max 150 characters).
- `max_capacity` (int): Maximum number of attendees allowed for the event.
- `names_per_active` (int): Number of names allowed per active attendee.

## Relationships
- `attendees`: One-to-many relationship with the Attendee model.

## Example Usage
```python
# Create a new event
new_event = Event(
    id="550e8400-e29b-41d4-a716-446655440000",
    name="Tech Conference 2023",
    date="2023-12-15",
    theme="Innovation in AI",
    max_capacity=500,
    names_per_active=2
)
db.session.add(new_event)
db.session.commit()