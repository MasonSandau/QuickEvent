# Server Health

Monitors server health and uptime.

## Route
- `/api/health`

## Methods
- `GET`: Returns server health metrics.

## Example Response
```json
{
  "cpu_usage": 25.5,
  "memory_usage": 60.2,
  "disk_usage": 45.0,
  "network_sent": 1024,
  "network_received": 2048,
  "uptime": "2 days, 3:45:12",
  "boot_time": "2023-09-28 08:00:00"
}