# DataTrust AI

[![Python Tests](https://github.com/warriorxxzz/datatrust-ai/actions/workflows/python-test.yml/badge.svg)](https://github.com/warriorxxzz/datatrust-ai/actions/workflows/python-test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)

![DataTrust AI Demo](demo.jpg)

A local PII (Personally Identifiable Information) scanner designed for AI chat interfaces.

It checks the text you are about to send to ChatGPT, Claude, or Gemini and warns you if it contains sensitive information like citizenship numbers, PANs, Aadhaar, or phone numbers. Everything runs locally on your device. No data is sent to any server.

## Why this exists

People casually paste personal information into AI chats. Once it's in the context window, you can't take it back. 

Most existing privacy tools are either enterprise-focused or heavily bloated. DataTrust AI is lightweight, built with Python's standard library, and specifically handles local formats like Nepali and Indian IDs. It also uses mathematical checksums to prevent false positives.

## Current Features

- **Nepal & India Patterns**: Detects Citizenship, NID, PAN, Aadhaar, UPI, Passport, and mobile numbers.
- **Devanagari Support**: Automatically normalizes Devanagari digits (`१२३`) to ASCII (`123`) before scanning.
- **Checksum Validation**: Uses the Luhn algorithm for Credit Cards and the Verhoeff algorithm for Aadhaar to ignore fake numbers.
- **Privacy-First**: The scanner never returns the actual detected value. It only returns the type and position of the match.
- **Lightweight**: Zero heavy dependencies. Uses Python's built-in `re` module.
- **Browser Extension**: Real-time warning banner directly inside the AI chat interface.

## How to use it

### 1. Command Line Interface (CLI)

You can install the package locally and use the `datatrust` command.

```bash
git clone https://github.com/warriorxxzz/datatrust-ai.git
cd datatrust-ai
pip install -e .
