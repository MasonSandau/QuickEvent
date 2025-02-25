# Dashboard Template

Displays the user dashboard based on their role.

## Features
- Admins are redirected to the events list.
- Active users are redirected to the active dashboard.

## Example
```html
<h1>Welcome, {{ username }}</h1>
<p>Role: {{ role }}</p>