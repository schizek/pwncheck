# Have I Been Pwned Password Checker

A Node.js script that checks passwords against the Have I Been Pwned API with intelligent caching to prevent duplicate API calls.

## Features

- **k-Anonymity**: Only sends the first 5 characters of the SHA-1 hash to the API (never sends actual passwords)
- **Smart Caching**: Caches API responses to avoid duplicate calls for passwords with the same hash prefix
- **Multiple Formats**: Supports plain text files (one password per line) or CSV files
- **Rate Limiting**: Includes delays between API calls to be respectful to the service
- **Progress Tracking**: Shows real-time progress and cache efficiency statistics

## Usage

```bash
# Make the script executable (optional)
chmod +x check-pwned-passwords.js

# Run with a text file
node check-pwned-passwords.js passwords.txt

# Run with a CSV file
node check-pwned-passwords.js passwords.csv

# Show passwords in output (use with caution)
node check-pwned-passwords.js passwords.txt --show-passwords
```

## Input File Formats

### Plain Text
```
password123
mySecureP@ssw0rd!
qwerty
```

### CSV
The script extracts passwords from the first column. Additional columns are ignored.

```csv
password123,user1,user1@example.com
"mySecureP@ssw0rd!",user2,user2@example.com
"password,with,commas",user3,user3@example.com
qwerty,user4,user4@example.com
```

## Example Output

```
Parsing passwords...
Found 6 password(s) to check

Progress: 6/6 (100.0%)

--- Results ---

(Line numbers correspond to your input file)

Line 1: ✗ PWNED (2,031,380 times)
Line 2: ✓ Safe
Line 3: ✗ PWNED (21,969,901 times)
Line 4: ✗ PWNED (1,138,064 times)
Line 5: ✗ PWNED (4,709,969 times)
Line 6: ✗ PWNED (6,298,374 times)

--- Summary ---
Total passwords checked: 6
Safe passwords: 1
Pwned passwords: 5

API calls made: 6
Results from cache: 0
Cache efficiency: 0.0%
```

### Showing Passwords in Output

By default, passwords are not displayed for security. To show passwords for compromised entries, use the `--show-passwords` flag:

```bash
node check-pwned-passwords.js passwords.txt --show-passwords
```

Output with flag:
```
Line 1: ✗ PWNED (2,031,380 times)
   Password: password123
Line 2: ✓ Safe
Line 3: ✗ PWNED (21,969,901 times)
   Password: qwerty
```

## How It Works

1. Reads passwords from input file
2. Calculates SHA-1 hash of each password
3. Sends only the first 5 characters of the hash to the API
4. API returns all hash suffixes matching that prefix
5. Script checks locally if the full hash matches any results
6. Results are cached to avoid duplicate API calls for similar passwords

## Privacy & Security

- Passwords are never sent over the network
- Uses k-anonymity model (only 5-char hash prefix is sent)
- API cannot determine which specific password you're checking
- All password hashing is done locally

## API Information

This script uses the [Have I Been Pwned Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords) which is free to use.
