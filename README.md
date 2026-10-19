# DataTrust AI

A local PII (Personally Identifiable Information) scanner designed for AI chat interfaces. 

It checks the text you are about to send to ChatGPT, Claude, or Gemini and warns you if it contains sensitive information like citizenship numbers, PANs, or phone numbers. Everything runs locally on your device. No data is sent to any server.

## Why this exists

People casually paste personal information into AI chats. Once it's in the context window, you can't take it back. 

Most existing privacy tools are either enterprise-focused or heavily bloated. DataTrust AI is lightweight, built with Python's standard library, and specifically handles local formats like Nepali IDs and Devanagari digits.

## Current Features

- **Nepal-First Patterns**: Detects Citizenship, NID, PAN, Passport, and NTC/Ncell mobile numbers.
- **Devanagari Support**: Automatically normalizes Devanagari digits (`१२३`) to ASCII (`123`) before scanning.
- **Global Patterns**: Basic detection for Emails, Credit Cards, and IPv4 addresses.
- **Privacy-First**: The scanner never returns the actual detected value. It only returns the type and position of the match.
- **Lightweight**: Zero heavy dependencies. Uses Python's built-in `re` module.

## How to use it

### 1. Clone the repository
```bash
git clone https://github.com/warriorxxzz/datatrust-ai.git
cd datatrust-ai
