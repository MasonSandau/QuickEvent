# QR Codes

Generates and validates QR codes for attendees.

## Routes
- `/attendee_form/<event_id>/<attendee_id>`: Generates a QR code.
- `/validate_attendee/<invite_code>`: Validates a QR code.

## Example QR Code Data
```json
{
  "validation_url": "http://example.com/validate_attendee/550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2023-10-01T12:00:00",
  "invite_code": "550e8400-e29b-41d4-a716-446655440000",
  "attendee_name": "Jane Doe"
}