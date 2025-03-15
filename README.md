# Dead Drop
Dead Drop is a command-line tool designed to send a preprogrammed message via email if a specific signal is not received within a given time period (default is 24 hours). This tool is inspired by the concept of dead drops used by spies in movies, providing a way to send critical information if the user is unable to do so manually.


## Features

- Host on any Unix or Windows system.
- Sends an email via SMTP (recommended: Gmail) if the signal is not received.
- Preprogrammed message can include references to encrypted files and/or raw text.
- Lightweight and easy to set up.

## Installation

Precompiled binaries are available in the GitHub releases tab. Download the appropriate binary for your system and run it.

## Usage

To set up Dead Drop, use the following command:

```bash
sudo dd setup

