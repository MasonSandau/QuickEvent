# Active Dashboard Template

Displays the dashboard for active users.

## Features
- Lists events and attendees invited by the active user.

## Example
```html
<h1>Active Dashboard</h1>
<h2>Events</h2>
<ul>
  {% for event in events %}
    <li>{{ event.name }}</li>
  {% endfor %}
</ul>