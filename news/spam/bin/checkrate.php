<?php
/*
 * checkrate.php - Simple file-based rate limiting for NNRPD spam filter
 * Originally part of novabbs.org news server anti-spam system
 *
 * RESTORED VERSION based on calling pattern analysis
 *
 * Usage: php checkrate.php "$user" "$myhash" "$mid" "$from" "$subject" "$newsgroups"
 *
 * Returns: Empty string = allow post, Error message = reject post
 * Side effect: Creates signal files in /news/spam/nnrpd/ratelimit/ if rate limited
 */

// Ensure we have the right number of arguments
if ($argc != 7) {
    error_log("checkrate.php: Invalid number of arguments ($argc)");
    echo "Invalid arguments";
    exit(1);
}

$user = $argv[1];
$myhash = $argv[2];        // SHA256 hex of user+body+subject
$mid = $argv[3];           // Message-ID
$from = $argv[4];          // From header
$subject = $argv[5];       // Subject header
$newsgroups = $argv[6];    // Newsgroups header

// Configuration
$rate_base_dir = "/news/spam/nnrpd/php_ratelimit/";
$user_rate_dir = "/news/spam/nnrpd/php_user_rates/";
$current_time = time();

// Rate limiting rules
$content_rate_limit = 300;    // 5 minutes between identical content (myhash)
$user_rate_limit = 60;        // 1 minute between posts per user
$user_hourly_limit = 50;      // Max 50 posts per hour per user

// Ensure directories exist
if (!is_dir($rate_base_dir)) {
    mkdir($rate_base_dir, 0755, true);
}
if (!is_dir($user_rate_dir)) {
    mkdir($user_rate_dir, 0755, true);
}

// Security: Use real username if safe, otherwise hash it
// Safe usernames: alphanumeric only, max 20 characters
function get_safe_username($user) {
    if (preg_match('/^[a-zA-Z0-9]{1,20}$/', $user)) {
        return $user;  // Safe to use directly
    } else {
        return hash('sha256', $user);  // Hash unsafe usernames
    }
}

// Security: Validate the myhash is a proper SHA256 hex (64 hex chars)
// If Perl sends malformed hash, something is wrong - reject the post
if (!preg_match('/^[a-fA-F0-9]{64}$/', $myhash)) {
    error_log("checkrate.php: Invalid hash format from Perl filter: " . substr($myhash, 0, 20) . "...");
    echo "Invalid hash format (bug in filter_nnrpd.pl sending malformed hash)";
    exit(1);
}
$content_hash = $myhash;  // Use directly - already validated
$user_safe = get_safe_username($user);

// 1. CHECK CONTENT-BASED RATE LIMITING (prevent rapid reposting of same content)
//
// Content hash explanation:
// - $myhash comes from Perl: SHA256(user+body+subject) in hex format
// - We clean it to ensure only hex characters for filesystem safety
// - Simple and direct - no complex HMAC or base64 encoding needed
// - This prevents identical content from being reposted within 5 minutes
// - Example: User "bob" posting "Hello world" creates the same hash every time
// - Different users posting same content = different hashes (user is part of hash)
// - Same user posting different content = different hashes (body/subject different)
//
$content_rate_file = $rate_base_dir . $content_hash;
if (file_exists($content_rate_file)) {
    $last_post_time = (int)file_get_contents($content_rate_file);
    $time_diff = $current_time - $last_post_time;

    if ($time_diff < $content_rate_limit) {
        $wait_time = $content_rate_limit - $time_diff;
        echo "Content Rate Limit Reached (wait " . gmdate("i:s", $wait_time) . ")";
        exit(1);
    }
}

// 2. CHECK USER-BASED RATE LIMITING (prevent rapid posting by same user)
$user_rate_file = $user_rate_dir . $user_safe;
if (file_exists($user_rate_file)) {
    $last_user_post = (int)file_get_contents($user_rate_file);
    $user_time_diff = $current_time - $last_user_post;

    if ($user_time_diff < $user_rate_limit) {
        $wait_time = $user_rate_limit - $user_time_diff;
        echo "User Rate Limit Reached (wait " . gmdate("i:s", $wait_time) . ")";
        exit(1);
    }
}

// 3. CHECK HOURLY POST LIMIT (prevent spam floods)
$hourly_file = $user_rate_dir . $user_safe . "_hourly";
$posts_this_hour = 0;
if (file_exists($hourly_file)) {
    $hourly_data = file_get_contents($hourly_file);
    list($hour_start, $post_count) = explode(":", $hourly_data);

    // Reset counter if it's a new hour
    if (($current_time - (int)$hour_start) >= 3600) {
        $posts_this_hour = 0;
        $hour_start = $current_time;
    } else {
        $posts_this_hour = (int)$post_count;
    }

    if ($posts_this_hour >= $user_hourly_limit) {
        $time_until_reset = 3600 - ($current_time - (int)$hour_start);
        echo "Hourly Post Limit Exceeded (resets in " . gmdate("i:s", $time_until_reset) . ")";
        exit(1);
    }
} else {
    $hour_start = $current_time;
}

// 4. CHECK FOR EXCESSIVE CROSS-POSTING
$newsgroup_count = count(preg_split('/[,\s]+/', trim($newsgroups)));
if ($newsgroup_count > 3) {
    // More restrictive rate limiting for cross-posts
    if (file_exists($content_rate_file)) {
        $last_post_time = (int)file_get_contents($content_rate_file);
        $time_diff = $current_time - $last_post_time;

        // Require 30 minutes between cross-posts
        if ($time_diff < 1800) {
            $wait_time = 1800 - $time_diff;
            echo "Cross-posting Rate Limit (wait " . gmdate("i:s", $wait_time) . ")";
            exit(1);
        }
    }
}

// 5. UPDATE RATE TRACKING FILES (post is allowed)
// Update content hash timestamp
file_put_contents($content_rate_file, $current_time);

// Update user timestamp
file_put_contents($user_rate_file, $current_time);

// Update hourly counter
$posts_this_hour++;
file_put_contents($hourly_file, $hour_start . ":" . $posts_this_hour);

// Clean up old rate limit files (older than 24 hours)
$cleanup_cutoff = $current_time - 86400;
foreach (glob($rate_base_dir . "*") as $file) {
    if (filemtime($file) < $cleanup_cutoff) {
        unlink($file);
    }
}

// Success - allow the post
echo "";
exit(0);
?>
