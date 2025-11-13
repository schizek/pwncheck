#!/usr/bin/env node

const crypto = require('crypto');
const https = require('https');
const fs = require('fs');
const path = require('path');

// Configuration constants
const API_RATE_LIMIT_DELAY_MS = 100;
const HASH_PREFIX_LENGTH = 5;

// ANSI color codes
const COLOR_GREEN = '\x1b[32m';
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
    const match = cachedData.find(entry => entry.suffix === suffix);
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
        'Add-Padding': 'true' // Optional: adds padding to results for additional privacy
      }
    };

    https.get(options, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        // Parse response and cache it
        const entries = data.split('\r\n')
          .filter(line => line.trim())
          .map(line => {
            const [suffix, count] = line.split(':');
            return { suffix: suffix.trim(), count: parseInt(count, 10) };
          });

        hashCache.set(prefix, entries);

        // Find matching suffix
        const match = entries.find(entry => entry.suffix === suffix);
        resolve(match ? match.count : 0);
      });
    }).on('error', (err) => {
      reject(err);
    });
  });
}

/**
 * Parse input file (CSV or text)
 * @param {string} filePath - Path to the input file
 * @returns {string[]} - Array of passwords
 */
function parseInputFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n').map(line => line.trim()).filter(line => line);

  // Detect CSV format by file extension
  const isCSV = filePath.toLowerCase().endsWith('.csv');
  
  if (isCSV) {
    // Parse CSV properly handling quoted fields with commas
    return lines.map(line => {
      // If line starts with a quote, find the closing quote
      if (line.startsWith('"')) {
        let endQuoteIndex = 1;
        while (endQuoteIndex < line.length) {
          endQuoteIndex = line.indexOf('"', endQuoteIndex);
          if (endQuoteIndex === -1) {
            // No closing quote found, return whole line
            return line.substring(1);
          }
          // Check if it's an escaped quote ("")
          if (line[endQuoteIndex + 1] === '"') {
            endQuoteIndex += 2; // Skip the escaped quote
            continue;
          }
          // Found the closing quote
          return line.substring(1, endQuoteIndex).replace(/""/g, '"');
        }
        return line.substring(1);
      }
      // Not quoted, just take first field up to comma
      return line.split(',')[0];
    }).filter(p => p);
  }

  // Plain text file, one password per line
  return lines;
}

/**
 * Add delay between requests to be respectful to the API
 */
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Main function
 */
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error('Usage: ./check-pwned-passwords.js <file> [--show-passwords]');
    console.error('   or: node check-pwned-passwords.js <file> [--show-passwords]');
    console.error('');
    console.error('  <file>: Path to a text file (one password per line) or CSV file');
    console.error('  --show-passwords: Optional flag to display passwords in results');
    process.exit(1);
  }

  const showPasswords = args.includes('--show-passwords');
  const filePath = path.resolve(args.filter(arg => !arg.startsWith('--'))[0]);

  if (!fs.existsSync(filePath)) {
    console.error(`\n❌ Error: File does not exist at the specified path\n`);
    console.error(`   Looking for: ${filePath}`);
    console.error(`\n💡 Tip: Make sure the file exists and the path is correct.`);
    console.error(`   Current directory: ${process.cwd()}\n`);
    process.exit(1);
  }

  console.log('Parsing passwords...');
  const passwords = parseInputFile(filePath);
  console.log(`Found ${passwords.length} password(s) to check\n`);

  const results = [];
  let checkedCount = 0;
  let cachedCount = 0;

  for (let i = 0; i < passwords.length; i++) {
    const password = passwords[i];
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
        status: count === 0 ? `${greenCheck} Safe` : `${redX} PWNED (${count.toLocaleString()} times)`
      });

      // Progress indicator
      const percent = ((i + 1) / passwords.length * 100).toFixed(1);
      process.stdout.write(`\rProgress: ${i + 1}/${passwords.length} (${percent}%)`);
    } catch (error) {
      const redX = `${COLOR_RED}✗${COLOR_RESET}`;
      results.push({
        password,
        count: -1,
        status: `${redX} Error: ${error.message}`
      });
    }
  }

  console.log('\n\n--- Results ---\n');
  console.log('(Line numbers correspond to your input file)\n');
  results.forEach((result, index) => {
    console.log(`Line ${index + 1}: ${result.status}`);
    if (showPasswords && (result.count > 0 || result.count === -1)) {
      console.log(`   Password: ${result.password}`);
    }
  });

  console.log('\n--- Summary ---');
  const safePasswords = results.filter(r => r.count === 0).length;
  const pwnedPasswords = results.filter(r => r.count > 0).length;
  const errors = results.filter(r => r.count === -1).length;

  console.log(`Total passwords checked: ${passwords.length}`);
  console.log(`Safe passwords: ${safePasswords}`);
  console.log(`Pwned passwords: ${pwnedPasswords}`);
  if (errors > 0) {
    console.log(`Errors: ${errors}`);
  }
  console.log(`\nAPI calls made: ${checkedCount}`);
  console.log(`Results from cache: ${cachedCount}`);
  console.log(`Cache efficiency: ${passwords.length > 0 ? ((cachedCount / passwords.length) * 100).toFixed(1) : 0}%`);
}

main().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
