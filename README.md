# DataTrust AI

[![PyPI version](https://badge.fury.io/py/datatrust-privacy-guard.svg)](https://badge.fury.io/py/datatrust-privacy-guard)
[![Python Tests](https://github.com/warriorxxzz/datatrust-ai/actions/workflows/python-test.yml/badge.svg)](https://github.com/warriorxxzz/datatrust-ai/actions/workflows/python-test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

![DataTrust AI Demo](demo.jpg)

A local PII (Personally Identifiable Information) scanner designed for AI chat interfaces.

It checks the text you are about to send to **120+ AI platforms** (including ChatGPT, Claude, Gemini, and DeepSeek) and warns you if it contains sensitive information like citizenship numbers, PANs, Aadhaar, or phone numbers. Everything runs locally on your device. No data is sent to any server.

## Why this exists

People casually paste personal information into AI chats. Once it's in the context window, you can't take it back. 

Most existing privacy tools are either enterprise-focused or heavily bloated. DataTrust AI is lightweight, built with Python's standard library, and specifically handles local formats like Nepali and Indian IDs. It also uses mathematical checksums to prevent false positives.

## Current Features

- **120+ AI Platforms Supported**: Works seamlessly on ChatGPT, Claude, Gemini, Copilot, Perplexity, DeepSeek, and many more.
- **Nepal & India Patterns**: Detects Citizenship, NID, PAN, Aadhaar, UPI, Passport, and mobile numbers.
- **Devanagari Support**: Automatically normalizes Devanagari digits (`१२३`) to ASCII (`123`) before scanning.
- **Checksum Validation**: Uses the Luhn algorithm for Credit Cards and the Verhoeff algorithm for Aadhaar to ignore fake numbers.
- **Privacy-First**: The scanner never returns the actual detected value. It only returns the type and position of the match.
- **Lightweight**: Zero heavy dependencies. Uses Python's built-in `re` module.
- **Browser Extension**: Real-time warning banner directly inside the AI chat interface.

## Challenges Faced While Building This

Building a full-stack cybersecurity tool entirely from an Android phone using Termux was not easy. Here are some real challenges I solved during development:

- **Mobile Development Environment**: Setting up Python, handling storage permissions (`termux-setup-storage`), and dealing with the Android file system restrictions.
- **PyPI Publishing Issues**: Tools like `twine` and `pydantic` failed to compile because they rely on Rust, which is difficult to set up on mobile. I solved this by switching to a pure Python approach using the built-in `http.server` module and the `flit` build backend.
- **Browser Caching**: The Lemur browser kept holding onto old cached JavaScript files, making it difficult to test the new UI. I had to learn how to force-reload unpacked extensions.
- **Regex Overlap**: Writing regex for local IDs (like Citizenship numbers) often caused them to overlap with phone numbers. I had to implement a sorting logic in `detector.py` to keep only the longest, most accurate match.

## How to use it

### 1. Command Line Interface (CLI)

You can install the package directly from PyPI.

```bash
pip install datatrust-privacy-guard
