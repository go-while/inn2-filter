## filter_nnrpd.pl
# NNRPD Spam Filter for INN (InterNetNews) - SECURITY HARDENED VERSION
# Originally for novabbs.org news server
#
# SECURITY IMPROVEMENTS MADE:
# ===========================
# - Added safe_filename_hash() to prevent path traversal attacks
# - Enhanced shell_escape() function for proper command injection prevention
# - Secure temporary file generation using File::Temp
# - Input sanitization for log files to prevent log injection
# - All user-controlled data hashed before filesystem operations
# - Control character filtering throughout
# - SpamAssassin checking made optional via config flag
# - Centralized rate limiting through checkrate.php (single source of truth)
#
# ARCHITECTURE:
# =============
# - checkrate.php: Handles ALL rate limiting logic and returns decisions directly
# - filter_nnrpd.pl: Trusts checkrate.php results, no redundant signal file checks
# - Organization header injection: Optional, configurable header addition
# - SpamAssassin integration: Optional spam detection via i2pn2-spamassassin.php
#
# MISSING FILES THAT NEED TO BE RESTORED:
# =====================================
# 1. /news/spam/bin/checkrate.php         - Rate limiting logic ✅ RESTORED
# 2. /news/spam/bin/i2pn2-spamassassin.php - SpamAssassin integration ✅ RESTORED
# 3. /etc/news/inn.conf                   - INN configuration ✅ NOW READING PATHHOST
#
# REQUIRED DIRECTORIES:
# ====================
# /news/spam/log/                  - Log files (nnrpd.log, debug.log)
# /news/spam/data/                 - Data files (posting_users.hash)
# /news/spam/nnrpd/check/          - Temp files for message processing
# /news/spam/nnrpd/found/          - Signal files for SpamAssassin detection
# /news/spam/nnrpd/php_user_rates/ - User rate tracking files (checkrate.php only)
# /news/spam/posted/               - Archive of posted messages
#
# REMOVED/UNUSED DIRECTORIES:
# ===========================
# /news/spam/nnrpd/fr_no_followup/ - OBSOLETE: Was for FR hierarchy rules
# /news/spam/nnrpd/ratelimit/      - OBSOLETE: Was for signal-based rate limiting
# /news/spam/nnrpd/multi/          - OBSOLETE: Was for multipost detection
# (These are now handled directly by checkrate.php return values)
#
# Do any initialization steps.
#
use Digest::SHA qw(hmac_sha256_base64 hmac_sha512_base64 sha256_hex sha512_hex sha1_hex);
use File::Copy;
use File::Temp qw(tempfile);

# Security function to sanitize and hash user inputs for filesystem operations
sub safe_filename_hash {
    my ($input) = @_;
    # Remove any null bytes and control characters
    $input =~ s/[\x00-\x1f\x7f-\x9f]//g;
    # Create a safe hash-based filename
    return sha256_hex($input);
}

# Security function to escape shell arguments properly
sub shell_escape {
    my ($arg) = @_;
    # Remove null bytes and control characters
    $arg =~ s/[\x00-\x1f\x7f-\x9f]//g;
    # Escape shell metacharacters more comprehensively
    $arg =~ s/([\$"`\\|;&<>(){}[\]*?~\s])/\\$1/g;
    return $arg;
}

# Function to read pathhost from inn.conf
sub read_pathhost_from_inn_conf {
    my $inn_conf = "/etc/news/inn.conf";
    my $pathhost = "";

    if (open(my $fh, '<', $inn_conf)) {
        while (my $line = <$fh>) {
            chomp $line;
            # Skip comments and empty lines
            next if $line =~ /^\s*#/ || $line =~ /^\s*$/;
            # Look for pathhost setting (with or without whitespace around colon)
            if ($line =~ /^\s*pathhost\s*:\s*(.+?)$/) {
                $pathhost = $1;
                $pathhost =~ s/^\s+|\s+$//g;  # Trim whitespace
                last;
            }
        }
        close $fh;
    }

    return $pathhost;
}

my %config = (
    hostpath          => "",        # Will be read from inn.conf
    trusted_servers   => "",        # Trusted relay servers/users
    enable_spamassassin => 0,       # Enable/disable SpamAssassin checking (1=enabled, 0=disabled)
    organization      => "",        # Optional Organization header to inject if none exists (empty = disabled)
    remove_headers    => "User-Agent,X-Newsreader,X-Mailer,X-User-Agent", # Comma-separated list of headers to remove for privacy (empty = disabled)
    checkincludedtext => 0,         # Check Quote option
    includedcutoff    => 40,        # Check Quote option
    includedratio     => 0.6,       # Check Quote option
    quotere           => '^[>:]',   # Check Quote option
    antiquotere       => '^[<]',    # so as not to reject dict(1) output
);

#
# Sample filter
#
sub filter_post {
    my $rval = "";    # assume we'll accept.
    $logfile = "/news/spam/log/nnrpd.log";
    $debuglog = "/news/spam/log/debug.log";
    $hashfile = "/news/spam/data/posting_users.hash";

    # DEBUG: Log filter start
    open(my $debug_fh, '>>', $debuglog);
    print $debug_fh "\n" . gmtime() . " DEBUG: filter_post started for user: $user";
    close $debug_fh;

    $ver = "SpamAssassin 4.0.0";

    $postingaccount = $user;

    # Read hostname from /etc/news/inn.conf
    my $hostpath = read_pathhost_from_inn_conf();
    if (!$hostpath) {
        # Fallback to hardcoded value if inn.conf reading fails
        $hostpath = "localhost";
        open(my $debug_fh_err, '>>', $debuglog);
        print $debug_fh_err "\n" . gmtime() . " WARNING: Could not read pathhost from inn.conf, using fallback: $hostpath";
        close $debug_fh_err;
    }

    # Update config with the read value for use in other functions
    $config{hostpath} = $hostpath;

    # SPECIAL HANDLING FOR TRUSTED NEWS SERVERS/USERS
    # ===============================================
    # This section handles posts from trusted news servers that may be relaying
    # posts from other systems (like web-to-news gateways or other news servers).
    #
    # For these trusted sources, we check for an "X-Rslight-Posting-User" header
    # which contains the REAL original poster's username (Rslight is a web-to-news gateway).
    # This allows proper attribution and rate limiting of the actual end user
    # rather than the gateway/relay system.
    if ( $user =~ /$config{trusted_servers}/ ) {
        if ( $hdr{"X-Rslight-Posting-User"} ne '') {
            # Use the real posting user from the X-Rslight header for injection info
            add_header_item(\%hdr, 'Injection-Info', $hdr{"X-Rslight-Posting-User"} );
            $postingaccount = $hdr{"X-Rslight-Posting-User"};  # Track the real user for rate limiting
        } else {
            # No X-Rslight header, use the relay/gateway user account
            add_header_item(\%hdr, 'Injection-Info', $user );
        }
    } else {
        # Regular NNTP user connection - use their authenticated username directly
        add_header_item(\%hdr, 'Injection-Info', $user );
    }
    set_message_id(\%hdr, 'Message-ID', $body);

    # DEBUG: Log after message-id generation
    open(my $debug_fh2, '>>', $debuglog);
    print $debug_fh2 "\n" . gmtime() . " DEBUG: message-id set to: " . $hdr{"Message-ID"};
    close $debug_fh2;

    # Inject Organization header if configured and not already present
    if ($config{organization} ne "" && !exists $hdr{"Organization"}) {
        add_header(\%hdr, 'Organization', $config{organization});
    }

    # Remove privacy-sensitive headers if configured
    if ($config{remove_headers} ne "") {
        my @headers_to_remove = split(/,\s*/, $config{remove_headers});
        foreach my $header_name (@headers_to_remove) {
            $header_name =~ s/^\s+|\s+$//g;  # Trim whitespace
            if (exists $hdr{$header_name}) {
                $hdr{$header_name} = undef;  # Use undef instead of delete as recommended by INN docs
                # DEBUG: Log header removal
                open(my $debug_fh_remove, '>>', $debuglog);
                print $debug_fh_remove "\n" . gmtime() . " DEBUG: removed header for privacy: $header_name";
                close $debug_fh_remove;
            }
        }
    }

    # Enable header modifications - must be set after all header changes
    $modify_headers = 1;

    # SECURITY FIX: Use hashed filenames instead of raw user data
    my $from_hash = safe_filename_hash($hdr{"From"});
    my $msgid_hash = safe_filename_hash($hdr{"Message-ID"});
    $postedfile = "/news/spam/posted/${from_hash}-${msgid_hash}";

    # SECURITY FIX: Use secure temporary file generation
    my ($temp_fh, $tempfile_path) = tempfile(
        "nnrpd_XXXXXX",
        DIR => "/news/spam/nnrpd/check/",
        SUFFIX => ".tmp",
        UNLINK => 0
    );
    my $tempfile_base = (split('/', $tempfile_path))[-1];  # Just the filename part

    if (not $temp_fh) {
        slog('E', "Cannot create secure temp file: $!");
        return $rval;
    }

    foreach (sort keys %hdr) {
        next if $_ eq '__BODY__' or $_ eq '__LINES__';
        print $temp_fh "$_: $hdr{$_}\n";
    };
    print $temp_fh "\n";
    print $temp_fh $body;
    close $temp_fh;

    $mid = $hdr{'Message-ID'};
    $from = $hdr{'From'};
    $subject = $hdr{'Subject'};
    $newsgroups = $hdr{'Newsgroups'};

    # SECURITY FIX: Proper shell escaping instead of minimal "Bork" escaping
    my $mid_safe = shell_escape($mid);
    my $from_safe = shell_escape($from);
    my $subject_safe = shell_escape($subject);
    my $newsgroups_safe = shell_escape($newsgroups);
    my $user_safe = shell_escape($user);

    $myhash = sha256_hex($user.$body.$subject);
    $arguments = '"' . $user_safe . '" "' . $myhash . '" "' . $mid_safe . '" "' . $from_safe . '" "' . $subject_safe . '" "' . $newsgroups_safe . '"';

    # DEBUG: Log before checkrate call
    open(my $debug_fh3, '>>', $debuglog);
    print $debug_fh3 "\n" . gmtime() . " DEBUG: calling checkrate.php with myhash: " . substr($myhash, 0, 16) . "...";
    close $debug_fh3;

    $rval = `/usr/bin/php /news/spam/bin/checkrate.php $arguments`;

    # DEBUG: Log after checkrate call
    open(my $debug_fh4, '>>', $debuglog);
    print $debug_fh4 "\n" . gmtime() . " DEBUG: checkrate.php returned: '$rval'";
    close $debug_fh4;

    # Check if checkrate.php rejected the post
    chomp($rval);  # Remove trailing newline
    if ($rval ne "") {
        # checkrate.php returned an error message - reject the post
        unlink($tempfile_path);  # Clean up temp file
        return $rval;  # Return the error message from checkrate.php
    }

    copy($tempfile_path, $postedfile);

    $note = '';

    # SpamAssassin integration - OPTIONAL (controlled by config flag)
    if ($config{enable_spamassassin}) {
        add_header(\%hdr, 'X-Spam-Checker-Version', $ver );
        $sa_arguments = '"' . $tempfile_base . '" "' . $mid_safe . '" "' . $from_safe . '" "' . $subject_safe . '" "' . $newsgroups_safe . '"';
        $spamvalue = `/usr/bin/php /news/spam/bin/i2pn2-spamassassin.php $sa_arguments`;
        $isspam = "/news/spam/nnrpd/found/".$tempfile_base;

        if (-e $isspam) {
            $rval = "Blocked by Filter";
            $note = "*SPAM* ";
            unlink($isspam);
            unlink($postedfile);
        }
    }

    # NOTE: Rate limiting is now handled entirely by checkrate.php
    # No need for redundant signal file checks here - checkrate.php is the single source of truth

    # Clean up temp file if we haven't copied it
    unlink($tempfile_path) if (-e $tempfile_path);

    # DEBUG: Log before final processing
    open(my $debug_fh5, '>>', $debuglog);
    print $debug_fh5 "\n" . gmtime() . " DEBUG: entering final processing, rval: '$rval'";
    close $debug_fh5;

    open(my $fh, '>>', $logfile);

    @grouplist = split(/[,\s]+/, $hdr{'Newsgroups'});
    $groupcnt = scalar @grouplist;

    if ($groupcnt > 6) {
        $note = $note . "*TOO MANY GROUPS* ";
        $rval = "Too Many Newsgroups";
    }

    my $postinghash = hmac_sha256_base64($config{hostpath}.$postingaccount);

    # SECURITY FIX: Sanitize data before logging to prevent log injection
    my $log_user = $user;
    my $log_from = $hdr{"From"};
    my $log_newsgroups = $hdr{"Newsgroups"};
    my $log_msgid = $hdr{"Message-ID"};

    # Remove control characters and newlines from log data
    $log_user =~ s/[\x00-\x1f\x7f-\x9f]/_/g;
    $log_from =~ s/[\x00-\x1f\x7f-\x9f]/_/g;
    $log_newsgroups =~ s/[\x00-\x1f\x7f-\x9f]/_/g;
    $log_msgid =~ s/[\x00-\x1f\x7f-\x9f]/_/g;

    print $fh "\n" . gmtime() . " Post in: " . $log_newsgroups;
    print $fh "\n    " . $note . "by: " . $log_user . " as " . $log_from;
    print $fh "\n    Status: " . $rval;
    print $fh "\n    posting-account: " . $postinghash;
    print $fh "\n    message-id: " . $log_msgid;
    close $fh;

    open(my $hashfh, '>>', $hashfile);
    print $hashfh "\n" . $postinghash . " : " .$log_user . " : " . $log_from;
    close $hashfh;  # BUG FIX: was closing $fh instead of $hashfh

    # DEBUG: Log filter completion
    open(my $debug_fh6, '>>', $debuglog);
    print $debug_fh6 "\n" . gmtime() . " DEBUG: filter_post completed, returning: '$rval'";
    close $debug_fh6;

    return $rval;
}

sub analyze {
    my ($lines, $quoted, $antiquoted) = (0, 0, 0);
    local $_ = shift;

    do {
        if (/\G$config{quotere}/mgc) {
            $quoted++;
        } elsif (/\G$config{antiquotere}/mgc) {
            $antiquoted++;
        }
    } while (/\G(.*)\n/gc && ++$lines);

    return ($lines, $quoted, $antiquoted);
}

sub add_header($$$) {
   my ( $r_hdr, $name, $value ) = @_;

   $r_hdr->{$name} = $value;
}

sub add_header_item($$$) {
   my ( $r_hdr, $name, $value ) = @_;

   # Use centralized hostname configuration
   my $prefix = $r_hdr->{$name};
   $myhash = hmac_sha256_base64($config{hostpath}.$value);
   my $injection = $r_hdr->{"Injection-Info"};

   $r_hdr->{$name} = $injection . ";\r\n\t" . 'posting-account="' .$myhash .'";';
}

sub set_message_id($$$) {
   my ( $r_hdr, $name, $value ) = @_;

   # Generate a new Message-ID
   my $msgid = $r_hdr->{"Subject"} . $r_hdr->{"From"} . $r_hdr->{"Newsgroups"} . ($r_hdr->{"References"} || "") . $value;
   $myhash = sha1_hex($config{hostpath}.$msgid);
   $r_hdr->{$name} = '<' . $myhash . '@' . $config{hostpath} . '>';
}

sub filter_end {
    # Do whatever you want to clean up things when Perl filtering is disabled.
}

# EOF # filter_nnrpd.pl