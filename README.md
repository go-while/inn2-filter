# INN2 PERL Filter - Security Hardened Version <<-- AI invented that -->>

A recovered and security-hardened NNRPD spam filter
for INN (InterNetNews) originally from novabbs.org / i2pn2.org.

## 🛡️ Security Improvements

This version has been completely security-hardened to
eliminate critical vulnerabilities found in the original code:

### ✅ Major Security Fixes Applied

1. **Path Traversal Prevention**
   - Added `safe_filename_hash()` function - all user data is SHA256 hashed before filesystem operations
   - No raw user data in file paths - prevents `../../../etc/passwd` attacks
   - All signal files use secure hashed filenames

2. **Command Injection Prevention**
   - Enhanced `shell_escape()` function with comprehensive metacharacter escaping
   - Escapes: `$`, `` ` ``, `"`, `\`, `|`, `;`, `&`, `<`, `>`, `(`, `)`, `{`, `}`, `[`, `]`, `*`, `?`, `~`, whitespace
   - Control character removal - strips null bytes and control chars

3. **Secure Temporary Files**
   - Replaced `rand(100)` with `File::Temp` - cryptographically secure temp files
   - Automatic cleanup and unpredictable filenames
   - No more race conditions

4. **Log Injection Prevention**
   - Input sanitization for logs - control characters replaced with `_`
   - Newline removal prevents log structure manipulation
   - Separate sanitized variables for logging

5. **Input Validation**
   - Control character filtering throughout the application
   - Null byte removal prevents null byte injection attacks

### 🔄 Security Example

**Before (vulnerable):**
```
User input: From: ../../../etc/passwd
File path: /news/spam/posted/../../../etc/passwd
Result: ATTACK SUCCEEDS ❌
```

**After (secure):**
```
User input: From: ../../../etc/passwd
Hashed: safe_filename_hash("../../../etc/passwd") → a1b2c3d4e5f6...
File path: /news/spam/posted/a1b2c3d4e5f6...-msgid_hash
Result: ATTACK BLOCKED ✅
```

## 📁 Project Structure

```
inn2-filter/
├── etc/news/filter/
│   └── filter_nnrpd.pl          # Main Perl spam filter (security hardened)
├── news/spam/bin/
│   ├── checkrate.php             # Rate limiting engine ✅ RESTORED
│   └── i2pn2-spamassassin.php    # SpamAssassin integration ✅ RESTORED
└── README.md                     # This file
```

### Required Runtime Directories

The following directories will be created automatically by the scripts:

```
/news/spam/
├── log/                  # Log files
├── data/                 # Data files (hashes, etc)
├── nnrpd/
│   ├── check/            # Temp files for checking
│   ├── found/            # Signal files for spam detection
│   ├── fr_no_followup/   # Signal files for FR hierarchy rules
│   ├── ratelimit/        # Signal files for rate limiting
│   ├── multi/            # Signal files for multipost detection
│   └── user_rates/       # User-based rate tracking
└── posted/               # Archive of posted messages
```

## 🚀 Components

### 1. Main Filter (`filter_nnrpd.pl`)

**Security-hardened Perl filter for INN NNRPD that:**
- Validates and sanitizes all inputs using hash-based filenames
- Integrates with SpamAssassin for content analysis
- Implements rate limiting to prevent spam floods
- Logs all activity securely without injection vulnerabilities
- Supports trusted relay servers (web-to-news gateways)

### 2. Rate Limiting Engine (`checkrate.php`)

**File-based rate limiting system featuring:**
- **Content-based limiting**: 5-minute cooldown between identical posts
- **User-based limiting**: 1-minute cooldown between posts from same user
- **Hourly limits**: Maximum 50 posts per hour per user
- **Cross-posting restrictions**: 30-minute cooldown for posts to >3 newsgroups
- **Automatic cleanup**: 24-hour file retention
- **Security**: Hash-based filenames, no raw user data on filesystem

### 3. SpamAssassin Integration (`i2pn2-spamassassin.php`)

**Secure SpamAssassin wrapper that:**
- Analyzes message content using SpamAssassin (`spamc` or `spamassassin`)
- Configurable spam threshold (default: 5.0)
- Creates signal files for detected spam
- Comprehensive logging with sanitized metadata
- Safe command execution via `proc_open()` - no shell injection possible

## ⚙️ Configuration

### Main Configuration (`filter_nnrpd.pl`)

```perl
my %config = (
    hostpath          => "novabbs.org",     # Your hostname
    trusted_servers   => "mm2021|rocksolidbbs\\.com|novabbs\\.(com|org)", # Trusted relays
    checkincludedtext => 0,
    includedcutoff    => 40,
    includedratio     => 0.6,
    quotere           => '^[>:]',           # Quote detection
    antiquotere       => '^[<]',            # Anti-quote detection
);
```

### Rate Limiting Configuration (`checkrate.php`)

```php
$content_rate_limit = 300;  # 5 minutes between identical content
$user_rate_limit = 60;      # 1 minute between posts from same user
$user_hourly_limit = 50;    # Max posts per hour per user
$crosspost_limit = 1800;    # 30 minutes for posts to >3 groups
```

### SpamAssassin Configuration (`i2pn2-spamassassin.php`)

```php
$SPAM_THRESHOLD = 5.0;      # SpamAssassin score threshold
```

## 🔧 Installation

1. **Copy filter to INN:**
   ```bash
   cp etc/news/filter/filter_nnrpd.pl /etc/news/filter/
   ```

2. **Install PHP components:**
   ```bash
   mkdir -p /news/spam/bin/
   cp news/spam/bin/*.php /news/spam/bin/
   chmod +x /news/spam/bin/*.php
   ```

3. **Configure INN to use the filter:**
   Add to `/etc/news/readers.conf`:
   ```
   auth "*" {
       hosts: "*"
       default: "<NOPASS>"
   }

   access "*" {
       users: "*"
       newsgroups: "*"
       perlfilter: true
   }
   ```

   And ensure `/etc/news/inn.conf` has:
   ```
   perlfilter: true
   ```

4. **Install dependencies:**
   ```bash
   # Perl modules
   cpan Digest::SHA File::Temp File::Copy

   # SpamAssassin
   apt-get install spamassassin  # or yum install spamassassin
   ```

## 📊 Monitoring

### Log Files

- **Main activity**: `/news/spam/log/nnrpd.log`
- **SpamAssassin**: `/news/spam/log/spamassassin.log`
- **User tracking**: `/news/spam/data/posting_users.hash`

### Log Format Example

```
2025-08-05 12:34:56 Post in: alt.test,misc.test
    by: testuser as test@example.com
    Status:
    posting-account: a1b2c3d4e5f6...
    message-id: <abcd1234@novabbs.org>
```

## ⚠️ Security Notes

- **All user data is hashed** before filesystem operations
- **No raw user input** appears in file paths
- **Shell commands are properly escaped** or avoided entirely
- **Temporary files are cryptographically secure**
- **Log injection is prevented** through input sanitization

## 📚 Background

This filter was originally deployed on novabbs.org/i2pn2.org news servers.
The original code contained severe security vulnerabilities including:

- Path traversal attacks via user headers
- Command injection through inadequate shell escaping
- Predictable temporary file generation
- Log injection vulnerabilities
- Raw user data in filesystem paths

This hardened version maintains all original functionality while eliminating these security risks.

## 🤝 Contributing

For security issues or improvements, please review the code carefully!
AND test in a safe environment before deployment!

---

**⚠️ Important**:
This code handles user input and executes system commands.
Always review security implications before deployment in production environments.
