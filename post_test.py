#!/usr/bin/env python3
"""
post_test.py - Real NNTP posting script with SSL and authentication

This script connects to a real NNTP server and posts messages with
proper authentication and SSL/TLS support. Useful for testing actual
news server functionality.

Usage:
    python3 post_test.py [options]

Examples:
    # Post to local server
    python3 post_test.py --server localhost --port 563 --ssl --user myuser --pass mypass

    # Post to external server
    python3 post_test.py --server news.example.com --user test@example.com --pass secret123

    # Post with custom message
    python3 post_test.py --server localhost --subject "My test" --body "Hello world"

    # Post to multiple newsgroups
    python3 post_test.py --server localhost --newsgroups "alt.test,comp.test"
"""

import argparse
import nntplib
import socket
import ssl
import sys
import time
import random
import re
from datetime import datetime
from email.utils import formatdate, parseaddr

class NNTPPoster:
    def __init__(self):
        self.server = None
        self.connected = False
        self.hostname = None

    def connect(self, hostname, port=119, use_ssl=False, username=None, password=None, timeout=30):
        """Connect to NNTP server with optional SSL and authentication"""
        try:
            print(f"Connecting to {hostname}:{port} (SSL: {use_ssl})...")

            if use_ssl:
                # Create SSL context
                context = ssl.create_default_context()
                # For testing with self-signed certificates, you might want:
                # context.check_hostname = False
                # context.verify_mode = ssl.CERT_NONE

                self.server = nntplib.NNTP_SSL(hostname, port, timeout=timeout, ssl_context=context)
            else:
                self.server = nntplib.NNTP(hostname, port, timeout=timeout)

            print(f"✓ Connected to {hostname}")
            print(f"Server welcome: {self.server.getwelcome()}")

            # Authenticate if credentials provided
            if username and password:
                print(f"Authenticating as {username}...")
                try:
                    self.server.login(username, password)
                    print("✓ Authentication successful")
                except nntplib.NNTPError as e:
                    print(f"✗ Authentication failed: {e}")
                    return False

            self.connected = True
            self.hostname = hostname
            return True

        except socket.gaierror as e:
            print(f"✗ DNS resolution failed: {e}")
            return False
        except socket.timeout as e:
            print(f"✗ Connection timeout: {e}")
            return False
        except ConnectionRefusedError as e:
            print(f"✗ Connection refused: {e}")
            return False
        except ssl.SSLError as e:
            print(f"✗ SSL error: {e}")
            return False
        except nntplib.NNTPError as e:
            print(f"✗ NNTP error: {e}")
            return False
        except Exception as e:
            print(f"✗ Connection error: {e}")
            return False

    def check_newsgroup(self, newsgroup):
        """Check if a newsgroup exists and we can post to it"""
        try:
            response, count, first, last, name = self.server.group(newsgroup)
            print(f"✓ Newsgroup {newsgroup}: {count} articles (range {first}-{last})")
            return True
        except nntplib.NNTPError as e:
            print(f"✗ Newsgroup {newsgroup} error: {e}")
            return False

    def create_message(self, from_addr, subject, newsgroups, body,
                      organization=None, reply_to=None, references=None):
        """Create a properly formatted NNTP message"""

        # Generate Message-ID using server hostname
        timestamp = int(time.time())
        random_part = random.randint(100000, 999999)
        message_id = f"<{timestamp}.{random_part}@{self.hostname}>"

        # Build message headers
        headers = [
            f"From: {from_addr}",
            f"Subject: {subject}",
            f"Newsgroups: {newsgroups}",
            f"Date: {formatdate(time.time(), True)}",
            f"Message-ID: {message_id}",
            f"User-Agent: post_test.py/1.1",
        ]

        # Add optional headers
        if organization:
            headers.append(f"Organization: {organization}")
        if reply_to:
            headers.append(f"Reply-To: {reply_to}")
        if references:
            headers.append(f"References: {references}")

        # Combine headers and body
        message = "\r\n".join(headers) + "\r\n\r\n" + body

        return message, message_id

    def post_message(self, from_addr, subject, newsgroups, body, **kwargs):
        """Post a message to the NNTP server"""
        if not self.connected:
            print("✗ Not connected to server")
            return False

        try:
            # Check if we can post to the newsgroups
            newsgroup_list = [ng.strip() for ng in newsgroups.split(',')]
            for newsgroup in newsgroup_list:
                if not self.check_newsgroup(newsgroup):
                    print(f"⚠ Warning: Issues with newsgroup {newsgroup}")

            # Create the message
            message, message_id = self.create_message(
                from_addr, subject, newsgroups, body, **kwargs
            )

            print(f"\nPosting message...")
            print(f"From: {from_addr}")
            print(f"Subject: {subject}")
            print(f"Newsgroups: {newsgroups}")
            print(f"Message-ID: {message_id}")
            print(f"Body length: {len(body)} characters")

            # Post the message
            response = self.server.post(message.encode('utf-8'))
            print(f"✓ Post successful: {response}")

            return True

        except nntplib.NNTPError as e:
            print(f"✗ Posting failed: {e}")
            return False
        except Exception as e:
            print(f"✗ Unexpected error during posting: {e}")
            return False

    def get_server_info(self):
        """Get information about the server"""
        if not self.connected:
            print("✗ Not connected to server")
            return

        try:
            # Get server date
            resp, date = self.server.date()
            print(f"Server date: {date}")

            # Try to get server help
            try:
                resp, help_text = self.server.help()
                print(f"Server help available: {len(help_text)} lines")
            except:
                print("Server help not available")

            # Try to get capabilities if available
            try:
                if hasattr(self.server, 'capabilities'):
                    caps = self.server.capabilities()
                    print(f"Server capabilities: {', '.join(caps)}")
            except:
                pass

        except Exception as e:
            print(f"Error getting server info: {e}")

    def disconnect(self):
        """Disconnect from the server"""
        if self.server and self.connected:
            try:
                self.server.quit()
                print("✓ Disconnected from server")
            except:
                pass
            self.connected = False

def create_test_message():
    """Create a standard test message"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""This is a test message posted at {timestamp}.

This message was generated by the post_test.py script for testing
NNTP server functionality and connectivity.

If you can read this message, the posting was successful!

Technical details:
- Posted via NNTPLIB Python library
- Timestamp: {timestamp}
- Script: post_test.py v1.1

TESTING ratelimit: https://github.com/go-while/inn2-filter

Best regards,
Test Script
"""

def main():
    parser = argparse.ArgumentParser(description='Post messages to NNTP servers')

    # Server connection
    parser.add_argument('--server', required=True,
                       help='NNTP server hostname')
    parser.add_argument('--port', type=int, default=119,
                       help='NNTP server port (default: 119, SSL: 563)')
    parser.add_argument('--ssl', action='store_true',
                       help='Use SSL/TLS connection')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Connection timeout in seconds (default: 30)')

    # Authentication
    parser.add_argument('--user', '--username',
                       help='Username for authentication')
    parser.add_argument('--pass', '--password', dest='password',
                       help='Password for authentication')

    # Message content
    parser.add_argument('--from', dest='from_addr', required=True,
                       help='From address (e.g., user@example.com)')
    parser.add_argument('--subject', default='Test Post',
                       help='Subject line (default: "Test Post")')
    parser.add_argument('--newsgroups', default='alt.test',
                       help='Newsgroups (comma-separated, default: alt.test)')
    parser.add_argument('--body', help='Message body (default: auto-generated test message)')

    # Optional headers
    parser.add_argument('--organization', help='Organization header')
    parser.add_argument('--reply-to', help='Reply-To header')
    parser.add_argument('--references', help='References header (for replies)')

    # Options
    parser.add_argument('--info', action='store_true',
                       help='Show server information and exit (no posting)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Connect and validate but do not post')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    # Set default SSL port if SSL is enabled and port is default
    if args.ssl and args.port == 119:
        args.port = 563
        print(f"SSL enabled, using default SSL port {args.port}")

    # Use default test message if no body provided
    if not args.body:
        args.body = create_test_message()

    # Validate required arguments
    if not args.from_addr:
        print("Error: --from is required")
        sys.exit(1)

    poster = NNTPPoster()

    try:
        # Connect to server
        if not poster.connect(args.server, args.port, args.ssl,
                            args.user, args.password, args.timeout):
            sys.exit(1)

        # Show server info if requested
        if args.info or args.verbose:
            poster.get_server_info()

        if args.info:
            print("Info mode - not posting message")
            return

        # Post message unless dry run
        if args.dry_run:
            print("Dry run mode - not actually posting")
            print(f"Would post to: {args.newsgroups}")
            print(f"Subject: {args.subject}")
            print(f"Body length: {len(args.body)} chars")
        else:
            success = poster.post_message(
                args.from_addr,
                args.subject,
                args.newsgroups,
                args.body,
                organization=args.organization,
                reply_to=args.reply_to,
                references=args.references
            )

            if success:
                print("\n✓ Message posted successfully!")
            else:
                print("\n✗ Message posting failed!")
                sys.exit(1)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        poster.disconnect()

if __name__ == '__main__':
    main()
