# Attendee Endpoints

## Invite Attendees
- **Route:** `/invite_attendees/<event_id>`
- **Method:** `POST`
- **Description:** Invites attendees to an event.

## Validate Attendee
- **Route:** `/validate_attendee/<invite_code>`
- **Method:** `GET`
- **Description:** Validates an attendee's QR code.

## Attendee Form
- **Route:** `/attendee_form/<event_id>/<attendee_id>`
- **Method:** `POST`
- **Description:** Updates attendee details and generates a QR code.