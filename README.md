# INN2 Perl Filter

# STATUS: UNSTABLE! TESTING!

This is a security-hardened NNTP spam filter for INN (InterNetNews) with a simplified, single-source-of-truth architecture.

## Architecture Overview

### Core Components

1. **filter_nnrpd.pl** - Main Perl filter that integrates with INN2
   - Handles header injection (Message-ID, Injection-Info, Organization)
   - Coordinates with external components
   - Performs final logging and accounting

2. **checkrate.php** - Centralized rate limiting (single source of truth)
   - User-based rate limiting (time between posts)
   - Content-based rate limiting (prevent rapid reposting)
   - Hourly post limits
   - Cross-posting restrictions
   - Returns decisions directly (no signal files)

3. **i2pn2-spamassassin.php** - Optional SpamAssassin integration
   - Spam detection using SpamAssassin
   - Signal file communication for spam detection results

### Key Design Principles

- **Single Source of Truth**: Only checkrate.php handles rate limiting
- **Direct Communication**: Return values instead of signal files for rate limiting
- **Security Hardened**: Input sanitization, secure file handling, path traversal prevention
- **Configurable**: Enable/disable components via config flags

## Directory Structure

### Required Directories
```
/news/spam/
├── log/                     # Log files
│   ├── nnrpd.log           # Main filter log
│   └── debug.log           # Debug output
├── data/                    # Data files
│   └── posting_users.hash  # User posting history
├── bin/                     # Executable scripts
│   ├── checkrate.php       # Rate limiting logic
│   └── i2pn2-spamassassin.php # SpamAssassin integration
├── nnrpd/
│   ├── check/              # Temporary message files
│   ├── found/              # SpamAssassin detection signals
│   └── php_user_rates/     # User rate tracking
└── posted/                 # Archive of posted messages
```

### Obsolete Directories (removed in clean architecture)
- `/news/spam/nnrpd/ratelimit/` - Old signal-based rate limiting
- `/news/spam/nnrpd/multi/` - Old multipost detection signals
- `/news/spam/nnrpd/fr_no_followup/` - Old FR hierarchy signals

## Configuration

### filter_nnrpd.pl Configuration
```perl
my %config = (
    hostpath            => "your.news.server",  # Hostname for Message-ID generation (read from inn.conf if empty)
    trusted_servers     => "trusted\\.server",  # Regex for trusted relay servers (  )
    enable_spamassassin => 0,                   # 1=enabled, 0=disabled
    organization        => "",                  # Optional Organization header (empty=disabled)
);
```

### checkrate.php Configuration
```php
$content_rate_limit = 300;    // 5 minutes between identical content
$user_rate_limit = 60;        // 1 minute between posts per user
$user_hourly_limit = 50;      // Max 50 posts per hour per user
```

## Installation

1. Run the setup script to create directories:
   ```bash
   chmod +x setup_directories.sh
   sudo ./setup_directories.sh
   ```

2. Copy filter files to appropriate locations:
   ```bash
   cp etc/news/filter/filter_nnrpd.pl /etc/news/filter/
   cp news/spam/bin/*.php /news/spam/bin/
   chmod +x /news/spam/bin/*.php
   ```

3. Configure INN to use the filter in `/etc/news/readers.conf`:
   ```
   access localhost {
       users: "*"
       auth: "ckpasswd -f /news/bbsuser.passwd"
       perlfilter: on
   }
   ```

## Features

### Security Enhancements
- Path traversal attack prevention
- Shell injection prevention
- Secure temporary file handling
- Input sanitization for logs
- Control character filtering

### Rate Limiting
- User-based rate limiting with wait times
- Content duplicate detection
- Hourly posting limits
- Cross-posting restrictions
- Clear error messages with remaining wait time

### Header Management
- Automatic Message-ID generation
- Injection-Info header with posting account hash
- Optional Organization header injection
- Support for trusted relay servers (X-Rslight-Posting-User)

### Logging & Monitoring
- Comprehensive logging with timestamps
- Debug logging for troubleshooting
- User posting history tracking
- Message archiving

## Error Messages

Rate limiting returns user-friendly messages:
- `User Rate Limit Reached (wait 01:23)` - 1 minute 23 seconds remaining
- `Content Rate Limit Reached (wait 04:17)` - 4 minutes 17 seconds remaining
- `Hourly Post Limit Exceeded (resets in 23:45)` - 23 minutes until reset
- `Cross-posting Rate Limit (wait 15:30)` - 15 minutes 30 seconds remaining

## Migration from Old Architecture

If migrating from the old signal-file based system:
1. Remove old signal file directories
2. Update any scripts that were manually creating signal files
3. All rate limiting logic is now centralized in checkrate.php

## Troubleshooting

Check debug logs for detailed operation flow:
```bash
tail -f /news/spam/log/debug.log
```

Common issues:
- Permission problems: Ensure news user can write to all directories
- PHP execution: Verify PHP path in filter (`/usr/bin/php`)
- Missing directories: Run setup script to create required structure
