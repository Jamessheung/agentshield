---
name: weather-lookup
description: Get current weather for any city using the OpenWeather API
version: "1.0.0"
metadata:
  openclaw:
    requires:
      env:
        - OPENWEATHER_API_KEY
    emoji: "🌤️"
    install:
      - id: jq
        kind: brew
        formula: jq
        bins:
          - jq
        label: jq (JSON processor)
---

# Weather Lookup

Get current weather conditions for any city worldwide.

## Usage

Ask the agent:
- "What's the weather in Tokyo?"
- "Is it going to rain in London today?"
- "Temperature in New York"

## How It Works

The skill uses the OpenWeather API to fetch current weather data.
It requires an API key set in the `OPENWEATHER_API_KEY` environment variable.

## Example Response

> The current weather in Tokyo is 22°C with partly cloudy skies.
> Humidity is at 65% with winds from the east at 12 km/h.
