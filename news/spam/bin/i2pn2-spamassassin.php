<?php
/**
 * i2pn2-spamassassin.php - SpamAssassin Integration for INN2 Filter
 *
 * SECURITY HARDENED VERSION
 * ========================
 * - All file paths use secure hashed temp filenames
 * - Input validation and sanitization
 * - Safe SpamAssassin execution via proc_open
 * - No shell injection vulnerabilities
 *
 * FUNCTIONALITY:
 * =============
 * 1. Receives email message in temporary file
 * 2. Runs SpamAssassin analysis via spamc/spamassassin
 * 3. Creates signal file if spam detected
 * 4. Returns spam score and status
 *
 * PARAMETERS:
 * ===========
 * $1 = tempfile_base - Secure hashed filename (no path traversal possible)
 * $2 = message_id    - Message-ID header (for logging)
 * $3 = from_address  - From header (for logging)
 * $4 = subject       - Subject header (for logging)
 * $5 = newsgroups    - Newsgroups header (for logging)
 *
 * SIGNAL FILES CREATED:
 * ====================
 * /news/spam/nnrpd/found/$tempfile_base - Created if message is spam
 *
 * DEPENDENCIES:
 * ============
 * - SpamAssassin installed (spamc or spamassassin command)
 * - Writable directories: /news/spam/nnrpd/found/, /news/spam/log/
 */

// Configuration
$SPAM_THRESHOLD = 5.0;  // SpamAssassin score threshold for marking as spam
$SPAM_DIRS = [
    'check'  => '/news/spam/nnrpd/check/',
    'found'  => '/news/spam/nnrpd/found/',
    'log'    => '/news/spam/log/'
];

// Ensure required directories exist
foreach ($SPAM_DIRS as $dir) {
    if (!is_dir($dir)) {
        if (!mkdir($dir, 0755, true)) {
            error_log("ERROR: Cannot create directory: $dir");
            exit(1);
        }
    }
}

// Input validation
if ($argc < 6) {
    error_log("ERROR: i2pn2-spamassassin.php requires 5 parameters");
    exit(1);
}

$tempfile_base = $argv[1];  // Already hashed and secure from Perl script
$message_id    = $argv[2];  // For logging only
$from_address  = $argv[3];  // For logging only
$subject       = $argv[4];  // For logging only
$newsgroups    = $argv[5];  // For logging only

// Security: Validate tempfile_base is just a filename (no path components)
if (strpos($tempfile_base, '/') !== false || strpos($tempfile_base, '\\') !== false) {
    error_log("ERROR: Invalid tempfile_base contains path separators: $tempfile_base");
    exit(1);
}

// Security: Additional validation - should be alphanumeric with allowed chars only
if (!preg_match('/^[a-zA-Z0-9._-]+$/', $tempfile_base)) {
    error_log("ERROR: Invalid tempfile_base contains unsafe characters: $tempfile_base");
    exit(1);
}

$message_file = $SPAM_DIRS['check'] . $tempfile_base;
$signal_file = $SPAM_DIRS['found'] . $tempfile_base;
$log_file = $SPAM_DIRS['log'] . 'spamassassin.log';

// Check if message file exists
if (!file_exists($message_file)) {
    error_log("ERROR: Message file not found: $message_file");
    exit(1);
}

// Function to safely execute SpamAssassin
function run_spamassassin($message_file) {
    // Try spamc first (faster client/daemon mode), fallback to spamassassin
    $commands = [
        'spamc -c < ' . escapeshellarg($message_file),
        'spamassassin --test-mode < ' . escapeshellarg($message_file)
    ];

    foreach ($commands as $cmd) {
        $descriptorspec = [
            0 => ["pipe", "r"],  // stdin
            1 => ["pipe", "w"],  // stdout
            2 => ["pipe", "w"]   // stderr
        ];

        $process = proc_open($cmd, $descriptorspec, $pipes);

        if (is_resource($process)) {
            // Read the file and send to SpamAssassin
            $message_content = file_get_contents($message_file);
            fwrite($pipes[0], $message_content);
            fclose($pipes[0]);

            // Read output
            $output = stream_get_contents($pipes[1]);
            $error = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);

            $return_value = proc_close($process);

            // spamc returns 0 for non-spam, 1 for spam
            // spamassassin in test mode outputs score info
            if ($return_value !== false) {
                return [
                    'success' => true,
                    'is_spam' => $return_value == 1, // spamc convention
                    'output' => $output,
                    'error' => $error,
                    'command' => explode(' ', $cmd)[0] // Just the command name
                ];
            }
        }
    }

    return [
        'success' => false,
        'is_spam' => false,
        'output' => '',
        'error' => 'SpamAssassin not available',
        'command' => 'none'
    ];
}

// Function to parse SpamAssassin score from output
function parse_spam_score($output) {
    // Look for patterns like "X-Spam-Score: 15.2" or "score=15.2"
    if (preg_match('/(?:X-Spam-Score:|score=)\s*([+-]?\d+\.?\d*)/', $output, $matches)) {
        return floatval($matches[1]);
    }

    // Fallback: look for hits/required pattern
    if (preg_match('/(\d+\.?\d*)\s*\/\s*(\d+\.?\d*)/', $output, $matches)) {
        return floatval($matches[1]);
    }

    return 0.0;
}

// Function to sanitize log data
function sanitize_for_log($data) {
    // Remove control characters and limit length
    $clean = preg_replace('/[\x00-\x1f\x7f-\x9f]/', '_', $data);
    return substr($clean, 0, 200); // Limit log line length
}

// Run SpamAssassin analysis
$result = run_spamassassin($message_file);

$is_spam = false;
$spam_score = 0.0;
$status = 'CLEAN';

if ($result['success']) {
    $spam_score = parse_spam_score($result['output']);
    $is_spam = $result['is_spam'] || ($spam_score >= $SPAM_THRESHOLD);
    $status = $is_spam ? 'SPAM' : 'CLEAN';

    // Create signal file if spam detected
    if ($is_spam) {
        if (touch($signal_file)) {
            // Signal file created successfully
        } else {
            error_log("ERROR: Cannot create spam signal file: $signal_file");
        }
    }
} else {
    $status = 'ERROR';
    error_log("ERROR: SpamAssassin execution failed: " . $result['error']);
}

// Log the analysis result
$log_entry = sprintf(
    "%s [%s] Score: %.2f Status: %s MID: %s From: %s Subject: %s Groups: %s\n",
    date('Y-m-d H:i:s'),
    $result['command'],
    $spam_score,
    $status,
    sanitize_for_log($message_id),
    sanitize_for_log($from_address),
    sanitize_for_log($subject),
    sanitize_for_log($newsgroups)
);

file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);

// Output result (captured by Perl script in $spamvalue, though not currently used)
echo "SCORE=$spam_score STATUS=$status";

// Exit with appropriate code
exit($is_spam ? 1 : 0);
?>
