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
#
# MISSING FILES THAT NEED TO BE RESTORED:
# =====================================
# 1. /news/spam/bin/checkrate.php         - Rate limiting logic ✅ RESTORED
# 2. /news/spam/bin/i2pn2-spamassassin.php - SpamAssassin integration ✅ RESTORED
# 3. /etc/inn/inn.conf                    - Should contain pathhost setting
#
# MISSING DIRECTORIES THAT NEED TO BE CREATED:
# ============================================
# /news/spam/log/                  - Log files
# /news/spam/data/                 - Data files (hashes, etc)
# /news/spam/nnrpd/check/          - Temp files for checking
# /news/spam/nnrpd/found/          - Signal files for spam detection
# /news/spam/nnrpd/fr_no_followup/ - Signal files for FR hierarchy rules
# /news/spam/nnrpd/ratelimit/      - Signal files for rate limiting
# /news/spam/nnrpd/multi/          - Signal files for multipost detection
# /news/spam/posted/               - Archive of posted messages
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

my %config = (
    hostpath          => "novabbs.org",        # Central hostname configuration
    trusted_servers   => "mm2021|rocksolidbbs\\.com|novabbs\\.(com|org)", # Trusted relay servers/users
    enable_spamassassin => 1,                  # Enable/disable SpamAssassin checking (1=enabled, 0=disabled)
    checkincludedtext => 0,
    includedcutoff    => 40,
    includedratio     => 0.6,
    quotere           => '^[>:]',
    antiquotere       => '^[<]',    # so as not to reject dict(1) output
);

#
# Sample filter
#
sub filter_post {
    my $rval = "";    # assume we'll accept.
    $logfile = "/news/spam/log/nnrpd.log";
    $hashfile = "/news/spam/data/posting_users.hash";

    $modify_headers = 1;
    $ver = "SpamAssassin 4.0.0";

    $postingaccount = $user;

    # MISSING FILE: Should read hostname from /etc/inn/inn.conf instead of hardcoding
    # TODO: Restore functionality to read pathhost from inn.conf
    my $hostpath = $config{hostpath};

    # SPECIAL HANDLING FOR TRUSTED NEWS SERVERS/USERS
    # ===============================================
    # This section handles posts from trusted news servers that may be relaying
    # posts from other systems (like web-to-news gateways or other news servers).
    #
    # - mm2021: Likely a trusted user account
    # - rocksolidbbs.com: Another BBS/news system that feeds into this server
    # - novabbs.com/org: The local domain(s) for this news server
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
    add_header(\%hdr, 'X-Spam-Checker-Version', $ver );

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

    $myhash = hmac_sha512_base64($user.$body.$subject);
    $arguments = '"' . $user_safe . '" "' . $myhash . '" "' . $mid_safe . '" "' . $from_safe . '" "' . $subject_safe . '" "' . $newsgroups_safe . '"';
    $rval = `/usr/bin/php /news/spam/bin/checkrate.php $arguments`;

    copy($tempfile_path, $postedfile);

    $note = '';

    # SpamAssassin integration - OPTIONAL (controlled by config flag)
    if ($config{enable_spamassassin}) {
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

# SECURITY FIX: Use hashed filenames for signal files to prevent path traversal
    my $mid_hash = safe_filename_hash($mid);
    my $myhash_safe = safe_filename_hash($myhash);

# FR HIERARCHY - Too Many Groups without Followup-To
    $is_fr_no_followup = "/news/spam/nnrpd/fr_no_followup/".$mid_hash;
    if (-e $is_fr_no_followup) {
        unlink($is_fr_no_followup);
        $rval = "Too Many Groups without Followup-To (fr.*)";
    }

    $is_ratelimit = "/news/spam/nnrpd/ratelimit/".$myhash_safe;
    if (-e $is_ratelimit) {
        unlink($is_ratelimit);
        $rval = "Posting Rate Limit Reached";
    }

    $is_multi = "/news/spam/nnrpd/multi/".$mid_hash;
    if (-e $is_multi) {
        unlink($is_multi);
        $rval = "Multipost not Allowed";
    }

    # Clean up temp file if we haven't copied it
    unlink($tempfile_path) if (-e $tempfile_path);

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

   # Use centralized hostname configuration
   if($r_hdr->{"Message-ID"} =~ /\@$config{hostpath}\>$/) {
       my $msgid = $r_hdr->{"Subject"} . $r_hdr->{"From"} . $r_hdr->{"Newsgroups"} . $r_hdr->{"References"} . $value;
       $myhash = sha1_hex($config{hostpath}.$msgid);
       $r_hdr->{$name} = '<' . $myhash . '@' . $config{hostpath} . '>';
   }
}

sub filter_end {
    # Do whatever you want to clean up things when Perl filtering is disabled.
}

# EOF # filter_nnrpd.pl