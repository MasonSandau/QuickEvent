# Event Management Template

Displays details and management options for a specific event.

## Features
- Shows event details.
- Lists attendees.
- Provides a link to invite attendees.

## Example
```html
<h1>{{ event.name }}</h1>
<p>Date: {{ event.date }}</p>
<p>Attendees: {{ num_attendees }}</p>
<a href="{{ active_link }}">Invite Attendees</a>