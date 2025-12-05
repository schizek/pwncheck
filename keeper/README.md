# Keeper Password Manager Integration

This guide explains how to check all passwords in your Keeper vault against the Have I Been Pwned database using Keeper Commander.

## Prerequisites

- Python 3.7 or higher
- Keeper account with Commander access enabled
- Admin must grant you API access permissions

## Installation

### 1. Install Keeper Commander

```bash
pip3 install keepercommander
```

### 2. Add Keeper to PATH

The keeper command should be in your Python bin directory. Add it to your shell profile:

**For zsh (macOS default):**
```bash
echo 'export PATH="/Library/Frameworks/Python.framework/Versions/3.12/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

**For bash:**
```bash
echo 'export PATH="/Library/Frameworks/Python.framework/Versions/3.12/bin:$PATH"' >> ~/.bash_profile
source ~/.bash_profile
```

### 3. Verify Installation

```bash
keeper --version
```

## Usage

### Option 1: Interactive Shell

Start Keeper Commander in interactive mode:

```bash
keeper shell
```

Login with your Keeper credentials and use commands like:
- `ls` - List all records
- `get <record_uid>` - View record details

### Option 2: Python Script (Recommended)

Use the Keeper Commander SDK to programmatically check passwords:

```python
from keepercommander import params, api

# Authenticate and iterate through vault
# Extract passwords in memory
# Check against HIBP API
# Display results
```

## Security Notes

- Passwords are processed in memory only
- No export files are created
- Uses Keeper's API (doesn't violate export restrictions)
- All HIBP checks use k-anonymity (only 5-char hash prefix sent)

## Troubleshooting

### "keeper: command not found"

Check if keeper is installed and find its location:
```bash
pip3 show keepercommander
python3 -m site --user-base
```

Find the keeper binary:
```bash
find /Library/Frameworks/Python.framework -name keeper 2>/dev/null
find ~/Library/Python -name keeper 2>/dev/null
```

### "Permission denied" or API errors

Contact your Keeper admin to:
1. Enable Commander access for your account
2. Grant API access permissions
3. Verify your account has necessary privileges

### Two-Factor Authentication

Keeper Commander supports 2FA. When logging in, you'll be prompted for your 2FA code.

## Next Steps

1. Test connection: `keeper shell`
2. Verify you can list records: `ls`
3. Run the password checker script (to be created)

## Links

- [Keeper Commander Documentation](https://docs.keeper.io/secrets-manager/commander-cli)
- [Keeper Commander GitHub](https://github.com/Keeper-Security/Commander)
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
