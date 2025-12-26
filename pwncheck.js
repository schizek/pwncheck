#!/usr/bin/env node

import crypto from 'crypto';
import https from 'https';
import fs from 'fs';
import path from 'path';

// Configuration constants
const API_RATE_LIMIT_DELAY_MS = 100;
const HASH_PREFIX_LENGTH = 5;

// ANSI color codes
const COLOR_GREEN = '\x1b[32m';
const COLOR_CYAN = '\x1b[36m';
const COLOR_DIM = '\x1b[2m';
const COLOR_RED = '\x1b[31m';
const COLOR_RESET = '\x1b[0m';

// Cache to prevent duplicate API calls
const hashCache = new Map();

/**
 * Calculate SHA-1 hash of a password
 */
function sha1(password) {
  return crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
}

/**
 * Check password against Have I Been Pwned API using k-anonymity
 * @param {string} password - The password to check
 * @returns {Promise<number>} - Number of times password has been pwned (0 if safe)
 */
async function checkPassword(password) {
  const hash = sha1(password);
  const prefix = hash.substring(0, HASH_PREFIX_LENGTH);
  const suffix = hash.substring(HASH_PREFIX_LENGTH);

  // Check cache first
  if (hashCache.has(prefix)) {
    const cachedData = hashCache.get(prefix);
    const match = cachedData.find((entry) => entry.suffix === suffix);
    return match ? match.count : 0;
  }

  // Make API request
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.pwnedpasswords.com',
      path: `/range/${prefix}`,
      method: 'GET',
      headers: {
        'User-Agent': 'Password-Checker-Script',
        'Add-Padding': 'true', // Optional: adds padding to results for additional privacy
      },
    };

    https
      .get(options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          // Parse response and cache it
          const entries = data
            .split('\r\n')
            .filter((line) => line.trim())
            .map((line) => {
              const [suffix, count] = line.split(':');
              return { suffix: suffix.trim(), count: parseInt(count, 10) };
            });

          hashCache.set(prefix, entries);

          // Find matching suffix
          const match = entries.find((entry) => entry.suffix === suffix);
          resolve(match ? match.count : 0);
        });
      })
      .on('error', (err) => {
        reject(err);
      });
  });
}

/**
 * Parse input file (CSV or text)
 * @param {string} filePath - Path to the input file
 * @returns {Object[]} - Array of objects with password and originalLineNumber
 */
function parseInputFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const result = [];

  // Detect CSV format by file extension
  const isCSV = filePath.toLowerCase().endsWith('.csv');

  lines.forEach((line, index) => {
    const trimmedLine = line.trim();
    if (!trimmedLine) return; // Skip blank lines

    let password;
    if (isCSV) {
      // Parse CSV properly handling quoted fields with commas
      if (trimmedLine.startsWith('"')) {
        let endQuoteIndex = 1;
        while (endQuoteIndex < trimmedLine.length) {
          endQuoteIndex = trimmedLine.indexOf('"', endQuoteIndex);
          if (endQuoteIndex === -1) {
            // No closing quote found, return whole line
            password = trimmedLine.substring(1);
            break;
          }
          // Check if it's an escaped quote ("")
          if (trimmedLine[endQuoteIndex + 1] === '"') {
            endQuoteIndex += 2; // Skip the escaped quote
            continue;
          }
          // Found the closing quote
          password = trimmedLine.substring(1, endQuoteIndex).replace(/""/g, '"');
          break;
        }
        if (!password) {
          password = trimmedLine.substring(1);
        }
      } else {
        // Not quoted, just take first field up to comma
        password = trimmedLine.split(',')[0];
      }
    } else {
      // Plain text file, one password per line
      password = trimmedLine;
    }

    if (password) {
      result.push({
        password: password,
        originalLineNumber: index + 1,
      });
    }
  });

  return result;
}

/**
 * Add delay between requests to be respectful to the API
 */
function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Escape a value for safe inclusion in a CSV file
 * @param {any} value
 * @returns {string}
 */
function escapeCsv(value) {
  if (value === null || value === undefined) return '';
  const str = String(value);
  if (/[",\n\r]/.test(str)) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

function renderProgressBar(current, total, found = 0, width = 30) {
  const ratio = total > 0 ? Math.min(current / total, 1) : 0;
  const filled = Math.round(ratio * width);
  const empty = Math.max(width - filled, 0);
  const bar = `${COLOR_GREEN}${'█'.repeat(filled)}${COLOR_DIM}${'░'.repeat(empty)}${COLOR_RESET}`;
  const percent = (ratio * 100).toFixed(1);
  return { bar, percent, found };
}

/**
 * Main function
 */
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error('Usage: ./check-pwned-passwords.js <file> [options]');
    console.error('   or: node check-pwned-passwords.js <file> [options]');
    console.error('');
    console.error('  <file>: Path to a text file (one password per line) or CSV file');
    console.error('');
    console.error('Options:');
    console.error('  --export-csv           Export results to a CSV file');
    console.error('  --include-passwords    Include passwords in CSV export (sensitive)');
    console.error('  --export-file <path>   Path to export CSV file');
    process.exit(1);
  }

  // Basic argument parsing
  const nonFlagArgs = args.filter((arg) => !arg.startsWith('--'));
  const filePath = path.resolve(nonFlagArgs[0]);

  const hasFlag = (name) => args.includes(name);

  const getFlagValue = (name) => {
    const prefix = `${name}=`;
    const direct = args.find((a) => a === name || a.startsWith(prefix));
    if (!direct) return null;
    if (direct.startsWith(prefix)) {
      return direct.slice(prefix.length);
    }
    const index = args.indexOf(direct);
    if (index !== -1 && args[index + 1] && !args[index + 1].startsWith('--')) {
      return args[index + 1];
    }
    return null;
  };

  const exportCsv = hasFlag('--export-csv');
  const includePasswords = hasFlag('--include-passwords');
  let exportFile = getFlagValue('--export-file');

  if (exportCsv && !exportFile) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    exportFile = path.join(process.cwd(), `pwned-password-results-${timestamp}.csv`);
  }

  if (!fs.existsSync(filePath)) {
    console.error(`\n❌ Error: File does not exist at the specified path\n`);
    console.error(`   Looking for: ${filePath}`);
    console.error(`\n💡 Tip: Make sure the file exists and the path is correct.`);
    console.error(`   Current directory: ${process.cwd()}\n`);
    process.exit(1);
  }

  if (includePasswords && !exportCsv) {
    console.error('\n⚠️  --include-passwords is only valid when used with --export-csv.');
    console.error(
      '   Passwords will not be printed to stdout; they are only included in the CSV export.\n'
    );
  }

  console.log('Parsing passwords...');
  const passwordEntries = parseInputFile(filePath);
  console.log(`Found ${passwordEntries.length} password(s) to check\n`);

  const results = [];
  let checkedCount = 0;
  let cachedCount = 0;
  let pwnedCount = 0;

  for (let i = 0; i < passwordEntries.length; i++) {
    const entry = passwordEntries[i];
    const password = entry.password;
    const hash = sha1(password);
    const prefix = hash.substring(0, HASH_PREFIX_LENGTH);

    // Track if this is a cached result
    const wasCached = hashCache.has(prefix);

    try {
      const count = await checkPassword(password);

      if (!wasCached) {
        checkedCount++;
        // Add delay after new API calls to respect rate limits
        await delay(API_RATE_LIMIT_DELAY_MS);
      } else {
        cachedCount++;
      }

      const greenCheck = `${COLOR_GREEN}✓${COLOR_RESET}`;
      const redX = `${COLOR_RED}✗${COLOR_RESET}`;

      results.push({
        password,
        count,
        originalLineNumber: entry.originalLineNumber,
        status:
          count === 0 ? `${greenCheck} Safe` : `${redX} PWNED (${count.toLocaleString()} times)`,
      });

      // Progress indicator
      if (count > 0) {
        pwnedCount++;
      }

      const { bar, percent, found } = renderProgressBar(i + 1, passwordEntries.length, pwnedCount);
      process.stdout.write(
        `\r${COLOR_CYAN}Progress:${COLOR_RESET} [${bar}] ${percent}% (${i + 1}/${passwordEntries.length}) | ${COLOR_GREEN}Pwned:${COLOR_RESET} ${found}`
      );
    } catch (error) {
      const redX = `${COLOR_RED}✗${COLOR_RESET}`;
      results.push({
        password,
        count: -1,
        originalLineNumber: entry.originalLineNumber,
        status: `${redX} Error: ${error.message}`,
      });
    }
  }

  if (passwordEntries.length > 0) {
    process.stdout.write('\n');
  }
  console.log('\n\n--- Results ---\n');
  console.log('(Line numbers correspond to your input file)\n');
  results.forEach((result) => {
    console.log(`Line ${result.originalLineNumber}: ${result.status}`);
  });

  console.log('\n--- Summary ---');
  const safePasswords = results.filter((r) => r.count === 0).length;
  const pwnedPasswords = results.filter((r) => r.count > 0).length;
  const errors = results.filter((r) => r.count === -1).length;

  console.log(`Total passwords checked: ${passwordEntries.length}`);
  console.log(`Safe passwords: ${safePasswords}`);
  console.log(`Pwned passwords: ${pwnedPasswords}`);
  if (errors > 0) {
    console.log(`Errors: ${errors}`);
  }
  console.log(`\nAPI calls made: ${checkedCount}`);
  console.log(`Results from cache: ${cachedCount}`);
  console.log(
    `Cache efficiency: ${passwordEntries.length > 0 ? ((cachedCount / passwordEntries.length) * 100).toFixed(1) : 0}%`
  );

  if (exportCsv) {
    try {
      const headers = ['line_number', 'pwned_count'];
      if (includePasswords) headers.push('password');

      const lines = [headers.join(',')];

      results.forEach((result) => {
        const row = [result.originalLineNumber, result.count >= 0 ? result.count : ''];
        if (includePasswords) {
          // Only include the password for pwned entries; leave blank for safe or error rows
          row.push(result.count > 0 ? result.password || '' : '');
        }
        lines.push(row.map(escapeCsv).join(','));
      });

      fs.writeFileSync(exportFile, lines.join('\n'), 'utf-8');
      console.log(`\nCSV export written to: ${exportFile}`);
      if (includePasswords) {
        console.log('⚠️  Export includes passwords. Handle this file as highly sensitive.');
      }
    } catch (error) {
      console.error('\n❌ Error writing CSV export:', error.message);
    }
  }
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
