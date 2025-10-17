#!/usr/bin/env python3
"""
Name: HashWizard: Identify and Classify Hash Types (2025 Edition)
version: 2.3
Date: October 1st 2025
Author: CyberPhvntom
Contact: angel@cenizalabs.com [redacted]


Description:
    HashWizard - Advanced Hash Identification Tool
    Updated with Hashcat 7.0+ and John the Ripper 2024+ hash types
    Including Argon2, LUKS2, MetaMask, OpenSSH, and modern formats
    Optimized for Kali Linux. Supports multi-threading and large datasets.

Copyright (c) 2025 Ceniza Labs, ShadowFax Labs (https://cenizalabs.com) (https://shadowfaxlabs.com)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: 

- You may convey verbatim copies of the Program's source code as you
receive it, in any medium, provided that you conspicuously and
appropriately publish on each copy an appropriate copyright notice;
keep intact all notices stating that this License and any
non-permissive terms added in accord with section 7 apply to the code;
keep intact all notices of the absence of any warranty; and give all
recipients a copy of this License along with the Program.

- Neither the name of the Ceniza Labs, ShadowFax Labs nor the names 
of its contributors may be used to endorse or promote products 
derived from this software without specific prior written permission.

-Additional conditions are listed in the LICENSE file.

- The GNU General Public License v3.0 (GPLv3) applies to this software 
and can be found in the LICENSE file included with this distribution. 
This license does not permit incorporation of this software into 
proprietary programs. For commercial licensing options, please contact 
the author.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, 
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

CHANGELOG v2.2:
- Added -sc/--suggested flag to optionally show cracking commands
- Suggested commands now only appear when explicitly requested with -sc flag

CHANGELOG v2.3:
- Modified -hc flag to also control Hashcat mode display in output
- Cleaner default output - only shows hash type name by default
- Use -hc to show Hashcat modes, -j to show John formats
"""

import argparse
import mimetypes
import os
import re
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import sys

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def setup_parser():
    parser = argparse.ArgumentParser(
        prog='HashWizard.py',
        description='Advanced hash identification with 2025 hash type database',
        usage='%(prog)s {-sh hash |-f file |-d directory} [-o output] [-hc] [-n] [-j] [-t threads] [-sc]'
    )
    argGroup = parser.add_mutually_exclusive_group(required=True)
    argGroup.add_argument("-sh", "--singleHash", type=str, help="Identify a single hash")
    argGroup.add_argument("-f", "--file", type=str, help="Parse a single file for hashes")
    argGroup.add_argument("-d", "--directory", type=str, help="Parse directory and subdirectories")
    parser.add_argument("-o", "--output", type=str, help="Output filename")
    parser.add_argument("-hc", "--hashcatOutput", action='store_true', help="Output separate files per hash type")
    parser.add_argument("-n", "--notFound", action='store_true', help="Include unidentifiable hashes")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of threads (default: 4)")
    parser.add_argument("-j", "--john", action='store_true', help="Show John the Ripper format names")
    parser.add_argument("-v", "--verbose", action='store_true', help="Verbose output with confidence scores")
    parser.add_argument("-sc", "--suggested", action='store_true', help="Show suggested cracking commands")
    return parser.parse_args()

# Comprehensive hash patterns database - Updated for 2025
HASH_PATTERNS = [
    
# Argon2
{
    'regex': re.compile(r'^\$argon2(id?|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$'),
    'types': [
        {'name': 'Argon2', 'hashcat': '34000', 'john': 'argon2', 'priority': 100},
    ]
},

# Django Argon2
{
    'regex': re.compile(r'^argon2\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$'),
    'types': [
        {'name': 'Django Argon2', 'hashcat': '34000', 'john': 'django-argon2', 'priority': 100},
    ]
},

# LUKS2
{
    'regex': re.compile(r'^\$luks\$2\$\d+\$[a-fA-F0-9]+\$.+'),
    'types': [
        {'name': 'LUKS2', 'hashcat': '29541', 'john': 'luks', 'priority': 100},
    ]
},

# MetaMask Wallet
{
    'regex': re.compile(r'^\$metamask\$[a-fA-F0-9]{64,}'),
    'types': [
        {'name': 'MetaMask Wallet', 'hashcat': '26600', 'john': None, 'priority': 100},
    ]
},

# OpenSSH Private Keys
{
    'regex': re.compile(r'^\$openssh\$\d+\$\d+\$\d+\$[a-fA-F0-9]+\$[a-fA-F0-9]+\$[a-fA-F0-9]+$'),
    'types': [
        {'name': 'OpenSSH Private Key', 'hashcat': '22911', 'john': 'SSH', 'priority': 100},
    ]
},

# Bitwarden
{
    'regex': re.compile(r'^\$bitwarden\$\d+\*\d+\*\d+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$'),
    'types': [
        {'name': 'Bitwarden', 'hashcat': '31000', 'john': None, 'priority': 100},
    ]
},

# KeePass KDBX4
{
    'regex': re.compile(r'^\$keepass\$\*4\*\d+\*.+'),
    'types': [
        {'name': 'KeePass KDBX4', 'hashcat': '29443', 'john': 'KeePass', 'priority': 100},
    ]
},

# KeePass KDBX3
{
    'regex': re.compile(r'^\$keepass\$\*2\*\d+\*.+'),
    'types': [
        {'name': 'KeePass KDBX3', 'hashcat': '13400', 'john': 'KeePass', 'priority': 95},
    ]
},

# Apple Keychain
{
    'regex': re.compile(r'^\$keychain\$\*[a-fA-F0-9]+\*[a-fA-F0-9]+'),
    'types': [
        {'name': 'Apple Keychain', 'hashcat': '23100', 'john': 'keychain', 'priority': 95},
    ]
},

# Microsoft Online Account
{
    'regex': re.compile(r'^\$MSOnline\$\d+\$[a-fA-F0-9]+\$[a-fA-F0-9]+$'),
    'types': [
        {'name': 'Microsoft Online Account', 'hashcat': '29411', 'john': None, 'priority': 100},
    ]
},

# SNMPv3 HMAC-SHA256
{
    'regex': re.compile(r'^\$SNMPv3\$4\$[a-fA-F0-9]+\$[a-fA-F0-9]+\$[a-fA-F0-9]+\$[a-fA-F0-9]+\$[a-fA-F0-9]+$'),
    'types': [
        {'name': 'SNMPv3 HMAC-SHA256', 'hashcat': '29821', 'john': None, 'priority': 100},
    ]
},

# SNMPv3 HMAC-SHA1
{
    'regex': re.compile(r'^\$SNMPv3\$3\$[a-fA-F0-9]+\$[a-fA-F0-9]+\$[a-fA-F0-9]+\$[a-fA-F0-9]+\$[a-fA-F0-9]+$'),
    'types': [
        {'name': 'SNMPv3 HMAC-SHA1', 'hashcat': '29721', 'john': None, 'priority': 100},
    ]
},

# GPG/PGP Private Key
{
    'regex': re.compile(r'^\$gpg\$\*\d+\*\d+\*\d+\*[a-fA-F0-9]+'),
    'types': [
        {'name': 'GPG/PGP Private Key', 'hashcat': '17010', 'john': 'gpg', 'priority': 100},
    ]
},
    
    # BitLocker
{
    'regex': re.compile(r'^\$bitlocker\$\d+\$\d+\$[a-fA-F0-9]+\$\d+\$\d+\$[a-fA-F0-9]+$'),
    'types': [
        {'name': 'BitLocker', 'hashcat': '22100', 'john': 'bitlocker', 'priority': 100},
    ]
},

# Azure Active Directory
{
    'regex': re.compile(r'^\$AzureAD\$\d+\$\d+\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]+$'),
    'types': [
        {'name': 'Azure Active Directory', 'hashcat': '33200', 'john': None, 'priority': 100},
    ]
},

# Bitcoin/Litecoin Wallet
{
    'regex': re.compile(r'^\$bitcoin\$\d+\$[a-fA-F0-9]+\$\d+\$[a-fA-F0-9]+\$\d+\$\d+\$[a-fA-F0-9]+$'),
    'types': [
        {'name': 'Bitcoin/Litecoin Wallet', 'hashcat': '11300', 'john': 'bitcoin', 'priority': 95},
    ]
},

# Ethereum Wallet
{
    'regex': re.compile(r'^\$ethereum\$[pw]\*\d+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$'),
    'types': [
        {'name': 'Ethereum Wallet', 'hashcat': '15700', 'john': 'ethereum', 'priority': 95},
    ]
},

# Monero Wallet
{
    'regex': re.compile(r'^\$monero\$\d+\$[a-fA-F0-9]+\$[a-fA-F0-9]+$'),
    'types': [
        {'name': 'Monero Wallet', 'hashcat': '31300', 'john': None, 'priority': 95},
    ]
},
    
    # NTDS Dump Format
{
    'regex': re.compile(r'^[a-zA-Z0-9._-]+:[0-9]+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::$'),
    'types': [
        {'name': 'NTDS Dump (NTLM hash)', 'hashcat': '1000', 'john': 'nt', 'priority': 100},
    ]
},

# NetNTLMv1
{
    'regex': re.compile(r'^[a-zA-Z0-9._-]+::[a-zA-Z0-9._-]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{48}:[a-fA-F0-9]{16}$'),
    'types': [
        {'name': 'NetNTLMv1', 'hashcat': '5500', 'john': 'netntlm', 'priority': 100},
    ]
},

# NetNTLMv2
{
    'regex': re.compile(r'^[a-zA-Z0-9._-]+::[a-zA-Z0-9._-]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$'),
    'types': [
        {'name': 'NetNTLMv2', 'hashcat': '5600', 'john': 'netntlmv2', 'priority': 100},
    ]
},

# Domain Cached Credentials 2
{
    'regex': re.compile(r'^\$DCC2\$\d+#[^#]+#[a-fA-F0-9]{32}$'),
    'types': [
        {'name': 'Domain Cached Credentials 2 (mscash2)', 'hashcat': '2100', 'john': 'mscash2', 'priority': 100},
    ]
},

# Kerberos 5 TGS-REP
{
    'regex': re.compile(r'^\$krb5tgs\$23\$\*[^\*]+\*\$[a-fA-F0-9]+$'),
    'types': [
        {'name': 'Kerberos 5 TGS-REP etype 23', 'hashcat': '13100', 'john': 'krb5tgs', 'priority': 100},
    ]
},

# Kerberos 5 AS-REP
{
    'regex': re.compile(r'^\$krb5asrep\$23\$[^\$]+\$[a-fA-F0-9]+$'),
    'types': [
        {'name': 'Kerberos 5 AS-REP etype 23', 'hashcat': '18200', 'john': 'krb5asrep', 'priority': 100},
    ]
},

# MD5/NTLM/MD4 (32 hex) 
{
    'regex': re.compile(r'^[a-fA-F0-9]{32}$'),
    'types': [
        {'name': 'NTLM', 'hashcat': '1000', 'john': 'nt', 'priority': 90},  # Lower
        {'name': 'MD5', 'hashcat': '0', 'john': 'raw-md5', 'priority': 90},  # Higher
        {'name': 'MD4', 'hashcat': '900', 'john': 'raw-md4', 'priority': 70},
        {'name': 'LM', 'hashcat': '3000', 'john': 'lm', 'priority': 60},
        {'name': 'Double MD5', 'hashcat': '2600', 'john': None, 'priority': 50},
    ]
},

# MD5 with salt
{
    'regex': re.compile(r'^[a-fA-F0-9]{32}:[a-zA-Z0-9+/=]+$'),
    'types': [
        {'name': 'md5($pass.$salt)', 'hashcat': '10', 'john': 'dynamic', 'priority': 90},
        {'name': 'md5($salt.$pass)', 'hashcat': '20', 'john': 'dynamic', 'priority': 85},
        {'name': 'Joomla < 3.2', 'hashcat': '11', 'john': 'joomla', 'priority': 80},
        {'name': 'osCommerce', 'hashcat': '21', 'john': None, 'priority': 75},
    ]
},

# SHA1 (40 hex)
{
    'regex': re.compile(r'^[a-fA-F0-9]{40}$'),
    'types': [
        {'name': 'SHA1', 'hashcat': '100', 'john': 'raw-sha1', 'priority': 95},
        {'name': 'sha1(LinkedIn)', 'hashcat': '190', 'john': 'raw-sha1-linkedin', 'priority': 85},
        {'name': 'RipeMD160', 'hashcat': '6000', 'john': 'ripemd-160', 'priority': 60},
        {'name': 'Tiger-160', 'hashcat': None, 'john': None, 'priority': 40},
    ]
},

# SHA1 with salt
{
    'regex': re.compile(r'^[a-fA-F0-9]{40}:[a-zA-Z0-9+/=]+$'),
    'types': [
        {'name': 'sha1($pass.$salt)', 'hashcat': '110', 'john': 'dynamic', 'priority': 90},
        {'name': 'sha1($salt.$pass)', 'hashcat': '120', 'john': 'dynamic', 'priority': 85},
        {'name': 'HMAC-SHA1 (key=$pass)', 'hashcat': '150', 'john': 'hmac-sha1', 'priority': 75},
    ]
},

# SHA256 (64 hex)
{
    'regex': re.compile(r'^[a-fA-F0-9]{64}$'),
    'types': [
        {'name': 'SHA256', 'hashcat': '1400', 'john': 'raw-sha256', 'priority': 95},
        {'name': 'SHA3-256 (Keccak)', 'hashcat': '5000', 'john': None, 'priority': 80},
        {'name': 'GOST R 34.11-94', 'hashcat': '6900', 'john': 'gost', 'priority': 50},
    ]
},

# SHA256 with salt
{
    'regex': re.compile(r'^[a-fA-F0-9]{64}:[a-zA-Z0-9+/=]+$'),
    'types': [
        {'name': 'sha256($pass.$salt)', 'hashcat': '1410', 'john': 'dynamic', 'priority': 90},
        {'name': 'sha256($salt.$pass)', 'hashcat': '1420', 'john': 'dynamic', 'priority': 85},
        {'name': 'HMAC-SHA256 (key=$pass)', 'hashcat': '1450', 'john': 'hmac-sha256', 'priority': 75},
    ]
},

# SHA384 (96 hex)
{
    'regex': re.compile(r'^[a-fA-F0-9]{96}$'),
    'types': [
        {'name': 'SHA384', 'hashcat': '10800', 'john': 'raw-sha384', 'priority': 95},
        {'name': 'SHA3-384 (Keccak)', 'hashcat': '17900', 'john': None, 'priority': 80},
    ]
},

# SHA512 (128 hex)
{
    'regex': re.compile(r'^[a-fA-F0-9]{128}$'),
    'types': [
        {'name': 'SHA512', 'hashcat': '1700', 'john': 'raw-sha512', 'priority': 95},
        {'name': 'Whirlpool', 'hashcat': '6100', 'john': 'whirlpool', 'priority': 70},
        {'name': 'SHA3-512 (Keccak)', 'hashcat': '17600', 'john': None, 'priority': 80},
    ]
},

# SHA512 with salt
{
    'regex': re.compile(r'^[a-fA-F0-9]{128}:[a-zA-Z0-9+/=]+$'),
    'types': [
        {'name': 'sha512($pass.$salt)', 'hashcat': '1710', 'john': 'dynamic', 'priority': 90},
        {'name': 'sha512($salt.$pass)', 'hashcat': '1720', 'john': 'dynamic', 'priority': 85},
        {'name': 'HMAC-SHA512 (key=$pass)', 'hashcat': '1750', 'john': 'hmac-sha512', 'priority': 75},
    ]
},

    
    # bcrypt - Modern standard
    {
        'regex': re.compile(r'^\$2[axyb]?\$[0-9]{2}\$[./A-Za-z0-9]{53}$'),
        'types': [
            {'name': 'bcrypt', 'hashcat': '3200', 'john': 'bcrypt', 'priority': 100},
        ]
    },
    
    # yescrypt (modern Linux)
    {
        'regex': re.compile(r'^\$y\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+'),
        'types': [
            {'name': 'yescrypt', 'hashcat': '70200', 'john': 'yescrypt', 'priority': 100},
        ]
    },
    
    # scrypt
    {
        'regex': re.compile(r'^\$scrypt\$[0-9]+\$[0-9]+\$[0-9]+\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]+$'),
        'types': [
            {'name': 'scrypt', 'hashcat': '8900', 'john': 'scrypt', 'priority': 95},
        ]
    },
    
    # MD5 crypt
    {
        'regex': re.compile(r'^\$1\$[a-zA-Z0-9./]{0,8}\$[a-zA-Z0-9./]{22}$'),
        'types': [
            {'name': 'md5crypt (Unix MD5)', 'hashcat': '500', 'john': 'md5crypt', 'priority': 100},
        ]
    },
    
    # SHA256 crypt
    {
        'regex': re.compile(r'^\$5\$(rounds=\d+\$)?[a-zA-Z0-9./]{0,16}\$[a-zA-Z0-9./]{43}$'),
        'types': [
            {'name': 'sha256crypt (Unix SHA256)', 'hashcat': '7400', 'john': 'sha256crypt', 'priority': 100},
        ]
    },
    
    # SHA512 crypt
    {
        'regex': re.compile(r'^\$6\$(rounds=\d+\$)?[a-zA-Z0-9./]{0,16}\$[a-zA-Z0-9./]{86}$'),
        'types': [
            {'name': 'sha512crypt (Unix SHA512)', 'hashcat': '1800', 'john': 'sha512crypt', 'priority': 100},
        ]
    },
    
    # DES crypt (traditional)
    {
        'regex': re.compile(r'^[a-zA-Z0-9./]{13}$'),
        'types': [
            {'name': 'descrypt (Traditional DES)', 'hashcat': '1500', 'john': 'descrypt', 'priority': 95},
        ]
    },
    
    # Django SHA1
    {
        'regex': re.compile(r'^sha1\$[a-zA-Z0-9]+\$[a-fA-F0-9]{40}$'),
        'types': [
            {'name': 'Django SHA1', 'hashcat': '800', 'john': 'django', 'priority': 100},
        ]
    },
    
    # Django SHA256
    {
        'regex': re.compile(r'^sha256\$[a-zA-Z0-9]+\$[a-fA-F0-9]{64}$'),
        'types': [
            {'name': 'Django SHA256', 'hashcat': '10000', 'john': 'django', 'priority': 100},
        ]
    },
    
    # Django PBKDF2 SHA256
    {
        'regex': re.compile(r'^pbkdf2_sha256\$\d+\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]+$'),
        'types': [
            {'name': 'Django PBKDF2-SHA256', 'hashcat': '10000', 'john': 'Django', 'priority': 100},
        ]
    },
    
    # phpass (WordPress, phpBB)
    {
        'regex': re.compile(r'^\$[PH]\$[a-zA-Z0-9./]{31}$'),
        'types': [
            {'name': 'phpass (WordPress/phpBB3)', 'hashcat': '400', 'john': 'phpass', 'priority': 100},
        ]
    },
    
    # Apache MD5
    {
        'regex': re.compile(r'^\$apr1\$[a-zA-Z0-9./]{0,8}\$[a-zA-Z0-9./]{22}$'),
        'types': [
            {'name': 'Apache MD5 (apr1)', 'hashcat': '1600', 'john': 'md5crypt', 'priority': 100},
        ]
    },
    
    # Drupal 7+
    {
        'regex': re.compile(r'^\$S\$[a-zA-Z0-9./]{52}$'),
        'types': [
            {'name': 'Drupal 7+', 'hashcat': '7900', 'john': 'drupal7', 'priority': 100},
        ]
    },
    
    # Joomla >= 3.2 (bcrypt)
    {
        'regex': re.compile(r'^\$2y\$\d+\$[./A-Za-z0-9]{53}$'),
        'types': [
            {'name': 'Joomla >= 3.2 (bcrypt)', 'hashcat': '3200', 'john': 'bcrypt', 'priority': 95},
        ]
    },
    
    # vBulletin < 3.8.5
    {
        'regex': re.compile(r'^[a-fA-F0-9]{32}:[a-zA-Z0-9]{3}$'),
        'types': [
            {'name': 'vBulletin < 3.8.5', 'hashcat': '2611', 'john': None, 'priority': 95},
        ]
    },
    
    # vBulletin >= 3.8.5
    {
        'regex': re.compile(r'^[a-fA-F0-9]{32}:[a-zA-Z0-9]{30}$'),
        'types': [
            {'name': 'vBulletin >= 3.8.5', 'hashcat': '2711', 'john': None, 'priority': 95},
        ]
    },
    
    # IPB2+, MyBB1.2+
    {
        'regex': re.compile(r'^[a-fA-F0-9]{32}:[a-zA-Z0-9]{5}$'),
        'types': [
            {'name': 'IPB2+/MyBB1.2+', 'hashcat': '2811', 'john': None, 'priority': 95},
        ]
    },
    
    # MySQL 4.1/5.x
    {
        'regex': re.compile(r'^\*[a-fA-F0-9]{40}$'),
        'types': [
            {'name': 'MySQL4.1/MySQL5', 'hashcat': '300', 'john': 'mysql-sha1', 'priority': 100},
        ]
    },
    
# MySQL 3.x / Oracle 7-10g / CRC64
{
    'regex': re.compile(r'^[a-fA-F0-9]{16}$'),
    'types': [
        {'name': 'MySQL 3.x', 'hashcat': '200', 'john': 'mysql', 'priority': 80},
        {'name': 'Oracle 7-10g (DES)', 'hashcat': '3100', 'john': 'oracle', 'priority': 75},
        {'name': 'CRC64', 'hashcat': None, 'john': None, 'priority': 25},
    ]
},

    
    # MSSQL 2000
    {
        'regex': re.compile(r'^0x0100[a-fA-F0-9]{88}$'),
        'types': [
            {'name': 'MSSQL 2000', 'hashcat': '131', 'john': 'mssql', 'priority': 100},
        ]
    },
    
    # MSSQL 2005
    {
        'regex': re.compile(r'^0x0100[a-fA-F0-9]{48}$'),
        'types': [
            {'name': 'MSSQL 2005', 'hashcat': '132', 'john': 'mssql05', 'priority': 100},
        ]
    },
    
    # MSSQL 2012+
    {
        'regex': re.compile(r'^0x0200[a-fA-F0-9]{136}$'),
        'types': [
            {'name': 'MSSQL 2012+', 'hashcat': '1731', 'john': 'mssql12', 'priority': 100},
        ]
    },
    
    # Oracle 11g
    {
        'regex': re.compile(r'^S:[a-fA-F0-9]{60}$'),
        'types': [
            {'name': 'Oracle 11g', 'hashcat': '112', 'john': 'oracle11', 'priority': 100},
        ]
    },
    
    # Oracle 12c/18c/19c
    {
        'regex': re.compile(r'^[a-fA-F0-9]{160}$'),
        'types': [
            {'name': 'Oracle 12c+', 'hashcat': '12300', 'john': 'oracle12c', 'priority': 100},
        ]
    },
    
    # PostgreSQL MD5 (FIXED - made more specific)
    {
    'regex': re.compile(r'^md5[a-fA-F0-9]{32}$'),
    'types': [
        {'name': 'PostgreSQL MD5', 'hashcat': '11', 'john': 'postgres', 'priority': 100},
    ]
    },
    
    # PostgreSQL SCRAM-SHA-256
    {
        'regex': re.compile(r'^SCRAM-SHA-256\$\d+:[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]+:[a-zA-Z0-9+/=]+$'),
        'types': [
            {'name': 'PostgreSQL SCRAM-SHA-256', 'hashcat': '28600', 'john': 'scram', 'priority': 100},
        ]
    },
    
    # WPA/WPA2
    {
        'regex': re.compile(r'^\$WPAPSK\$[^#]+#[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+:.+$'),
        'types': [
            {'name': 'WPA/WPA2 PSK', 'hashcat': '22000', 'john': 'wpapsk', 'priority': 100},
        ]
    },
    
    # WPA-PMKID
    {
        'regex': re.compile(r'^[a-fA-F0-9]{32}\*[a-fA-F0-9]{12}\*[a-fA-F0-9]{12}\*[a-fA-F0-9]+$'),
        'types': [
            {'name': 'WPA-PMKID', 'hashcat': '22000', 'john': 'wpapsk-pmkid', 'priority': 100},
        ]
    },
    
    # WPA3
    {
    'regex': re.compile(r'^\$WPA3\$[a-fA-F0-9]+\$[a-fA-F0-9]+$'),
    'types': [
        {'name': 'WPA3', 'hashcat': '22000', 'john': None, 'priority': 100},
    ]
    },

    # IKE PSK
     {
    'regex': re.compile(r'^[a-fA-F0-9]{40}:[a-fA-F0-9]{40}:[a-fA-F0-9]{40}:[a-fA-F0-9]+$'),
    'types': [
        {'name': 'IKE-PSK MD5/SHA1', 'hashcat': '5300', 'john': None, 'priority': 90},
    ]
    },
    
    # IPMI2 RAKP HMAC-SHA1
    {
        'regex': re.compile(r'^[a-fA-F0-9]{130}$'),
        'types': [
            {'name': 'IPMI2 RAKP HMAC-SHA1', 'hashcat': '7300', 'john': 'rakp', 'priority': 95},
        ]
    },
    
    # Cisco IOS SHA256 
{
    'regex': re.compile(r'^[a-zA-Z0-9./]{43}$'),
    'types': [
        {'name': 'Cisco-IOS SHA256', 'hashcat': '5700', 'john': None, 'priority': 70},
    ]
},

# Cisco-PIX MD5 
{
    'regex': re.compile(r'^[a-zA-Z0-9./]{16}$'),
    'types': [
        {'name': 'Cisco-PIX MD5', 'hashcat': '2400', 'john': 'pix-md5', 'priority': 75},
        {'name': 'CRC64', 'hashcat': None, 'john': None, 'priority': 25},  # DUPLICATE - may conflict
    ]
},

# Cisco Type 4 
{
    'regex': re.compile(r'^[a-zA-Z0-9./]{32}$'),
    'types': [
        {'name': 'Cisco Type 4', 'hashcat': '5700', 'john': None, 'priority': 70},
    ]
},
    
    # Cisco Type 7 
{
    'regex': re.compile(r'^[0-9]{2}[a-fA-F0-9]{4,}$'),
    'types': [
        {'name': 'Cisco Type 7 (weak encryption)', 'hashcat': None, 'john': 'cisco7', 'priority': 75},
    ]
},
    
    # LDAP SHA
    {
        'regex': re.compile(r'^\{SHA\}[a-zA-Z0-9+/=]{27,28}'),
        'types': [
            {'name': 'LDAP SHA', 'hashcat': '101', 'john': 'nsldap', 'priority': 100},
        ]
    },
    
    # LDAP SSHA
    {
        'regex': re.compile(r'^\{SSHA\}[a-zA-Z0-9+/=]{28,}'),
        'types': [
            {'name': 'LDAP SSHA', 'hashcat': '111', 'john': 'nsldaps', 'priority': 100},
        ]
    },
    
    # LDAP SSHA256
    {
        'regex': re.compile(r'^\{SSHA256\}[a-zA-Z0-9+/=]{44,}'),
        'types': [
            {'name': 'LDAP SSHA256', 'hashcat': '21800', 'john': None, 'priority': 100},
        ]
    },
    
    # LDAP SSHA512
    {
        'regex': re.compile(r'^\{SSHA512\}[a-zA-Z0-9+/=]{88,}'),
        'types': [
            {'name': 'LDAP SSHA512', 'hashcat': '1711', 'john': None, 'priority': 100},
        ]
    },
    
    # macOS v10.8+ 
{
    'regex': re.compile(r'^\$ml\$\d+\$[a-fA-F0-9]+\$[a-fA-F0-9]{128}$'),
    'types': [
        {'name': 'macOS v10.8+ (PBKDF2-SHA512)', 'hashcat': '7100', 'john': 'xsha512', 'priority': 100},
    ]
},

# macOS v10.7 
{
    'regex': re.compile(r'^[a-fA-F0-9]{136}$'),
    'types': [
        {'name': 'macOS v10.7', 'hashcat': '1722', 'john': 'xsha512', 'priority': 90},
    ]
},

# macOS v10.4-10.6
{
    'regex': re.compile(r'^[a-fA-F0-9]{48}$'),
    'types': [
        {'name': 'macOS v10.4-10.6', 'hashcat': '122', 'john': 'xsha', 'priority': 85},
    ]
},

# Android PIN
{
    'regex': re.compile(r'^[a-fA-F0-9]{40}:[a-fA-F0-9]{40}$'),
    'types': [
        {'name': 'Samsung Android Password/PIN', 'hashcat': '5800', 'john': None, 'priority': 95},
    ]
},
    
    # Android Backup
    {
        'regex': re.compile(r'^[a-fA-F0-9]{192}'),
        'types': [
            {'name': 'Android Backup', 'hashcat': '13900', 'john': 'androidbackup', 'priority': 95},
        ]
    },
    
    # 7-Zip
{
    'regex': re.compile(r'^\$7z\$\d+\$\d+\$\d+\$[a-fA-F0-9]+\$\d+\$[a-fA-F0-9]+\$\d+\$[a-fA-F0-9]+$'),
    'types': [
        {'name': '7-Zip', 'hashcat': '11600', 'john': '7z', 'priority': 100},
    ]
},

# RAR3 
{
    'regex': re.compile(r'^\$RAR3\$\*\d+\*[a-fA-F0-9]+\*[a-fA-F0-9]+$'),
    'types': [
        {'name': 'RAR3-hp', 'hashcat': '12500', 'john': 'rar', 'priority': 100},
    ]
},

# RAR5
{
    'regex': re.compile(r'^\$rar5\$\d+\$[a-fA-F0-9]+\$\d+\$[a-fA-F0-9]+\$\d+\$[a-fA-F0-9]+$'),
    'types': [
        {'name': 'RAR5', 'hashcat': '13000', 'john': 'rar5', 'priority': 100},
    ]
},

# ZIP (WinZip/PKZIP)
{
    'regex': re.compile(r'^\$zip2\$\*\d+\*\d+\*\d+\*[a-fA-F0-9]+.*$'),
    'types': [
        {'name': 'ZIP (PKZIP)', 'hashcat': '13600', 'john': 'zip', 'priority': 95},
    ]
},

# ZIP (AES)
{
    'regex': re.compile(r'^\$zip3\$\*\d+\*\d+\*\d+\*[a-fA-F0-9]+.*$'),
    'types': [
        {'name': 'ZIP (AES)', 'hashcat': '13600', 'john': 'zip', 'priority': 100},
    ]
},

# PDF 1.4-1.6
{
    'regex': re.compile(r'^\$pdf\$[245]\*[34]\*128\*-?\d+\*\d+\*\d+\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+.*$'),
    'types': [
        {'name': 'PDF 1.4-1.6', 'hashcat': '10500', 'john': 'pdf', 'priority': 95},
    ]
},

# PDF 1.7+
{
    'regex': re.compile(r'^\$pdf\$[5-6]\*[5-6]\*256\*-?\d+\*\d+\*\d+\*[a-fA-F0-9]+.*$'),
    'types': [
        {'name': 'PDF 1.7+', 'hashcat': '10700', 'john': 'pdf', 'priority': 100},
    ]
},

# Office 2007
{
    'regex': re.compile(r'^\$office\$\*2007\*\d+\*\d+\*\d+\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+.*$'),
    'types': [
        {'name': 'MS Office 2007', 'hashcat': '9400', 'john': 'office', 'priority': 95},
    ]
},

# Office 2010
{
    'regex': re.compile(r'^\$office\$\*2010\*\d+\*\d+\*\d+\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+.*$'),
    'types': [
        {'name': 'MS Office 2010', 'hashcat': '9500', 'john': 'office', 'priority': 95},
    ]
},

# Office 2013
{
    'regex': re.compile(r'^\$office\$\*2013\*\d+\*\d+\*\d+\*[a-fA-F0-9]+\*[a-fA-F0-9]+\*[a-fA-F0-9]+.*$'),
    'types': [
        {'name': 'MS Office 2013', 'hashcat': '9600', 'john': 'office', 'priority': 100},
    ]
},

# 1Password
{
    'regex': re.compile(r'^[a-zA-Z0-9+/=]{64,}:[a-zA-Z0-9+/=]+$'),
    'types': [
        {'name': '1Password (Agile Keychain)', 'hashcat': '6600', 'john': '1password', 'priority': 70},
    ]
},

# LastPass
{
    'regex': re.compile(r'^[a-zA-Z0-9+/=]+:[a-zA-Z0-9+/=]+@[a-zA-Z0-9.-]+$'),
    'types': [
        {'name': 'LastPass', 'hashcat': '6800', 'john': 'lastpass', 'priority': 90},
    ]
},

# BLAKE2b-512
{
    'regex': re.compile(r'^\$BLAKE2\$[a-fA-F0-9]{128}$'),
    'types': [
        {'name': 'BLAKE2b-512', 'hashcat': '600', 'john': 'raw-blake2', 'priority': 90},
    ]
},

# CRC32
{
    'regex': re.compile(r'^[a-fA-F0-9]{8}$'),
    'types': [
        {'name': 'CRC32', 'hashcat': None, 'john': None, 'priority': 30},
    ]
},
    
]
def identify_hash_advanced(hash_string):
    """Advanced hash identification using regex patterns with probability scoring."""
    hash_string = hash_string.strip()
    matches = []
    
    for pattern_group in HASH_PATTERNS:
        if pattern_group['regex'].match(hash_string):
            for hash_type in pattern_group['types']:
                matches.append(hash_type.copy())
    
    # Sort by priority (higher is more likely)
    matches.sort(key=lambda x: x['priority'], reverse=True)
    
    return matches

def format_hash_output(hash_string, matches, show_john=False, verbose=False, show_hashcat=False):
    """Format hash identification output with color coding."""
    output = []
    output.append(f"\n{Colors.BOLD}{Colors.CYAN}Hash:{Colors.END} {hash_string}")
    output.append(f"{Colors.BOLD}Length:{Colors.END} {len(hash_string)}")
    
    if not matches:
        output.append(f"{Colors.RED}[!] No matches found{Colors.END}")
        return '\n'.join(output)
    
    output.append(f"\n{Colors.BOLD}{Colors.GREEN}Possible Hash Types:{Colors.END}")
    
    # Most likely match
    most_likely = matches[0]
    output.append(f"\n  {Colors.BOLD}Most Likely:{Colors.END}")
    output.append(f"  {Colors.GREEN}[★]{Colors.END} {most_likely['name']}")
    if show_hashcat and most_likely['hashcat']:
        output.append(f"      Hashcat Mode: {Colors.YELLOW}{most_likely['hashcat']}{Colors.END}")
    if show_john and most_likely['john']:
        output.append(f"      John Format: {Colors.YELLOW}{most_likely['john']}{Colors.END}")
    if verbose:
        output.append(f"      Confidence: {Colors.CYAN}{most_likely['priority']}%{Colors.END}")
    
    # Other possible matches
    if len(matches) > 1 and verbose:
        output.append(f"\n  {Colors.BOLD}Other Possibilities:{Colors.END}")
        for match in matches[1:4]:  # Show top 3 alternatives
            output.append(f"  {Colors.YELLOW}[•]{Colors.END} {match['name']}")
            if show_hashcat and match['hashcat']:
                output.append(f"      Hashcat Mode: {match['hashcat']}")
            if show_john and match['john']:
                output.append(f"      John Format: {match['john']}")
            if verbose:
                output.append(f"      Confidence: {match['priority']}%")
    
    return '\n'.join(output)

def process_single_hash(hash_string, show_john=False, verbose=False, show_suggested=False, show_hashcat=False):
    """Process and display information about a single hash."""
    matches = identify_hash_advanced(hash_string)
    output = format_hash_output(hash_string, matches, show_john, verbose, show_hashcat)
    print(output)
    
    # Provide cracking suggestions only if requested with -sc flag
    if show_suggested and matches:
        most_likely = matches[0]
        print(f"\n{Colors.BOLD}{Colors.BLUE}Suggested Commands:{Colors.END}")
        if most_likely['hashcat']:
            print(f"  {Colors.CYAN}hashcat -m {most_likely['hashcat']} -a 0 hash.txt wordlist.txt{Colors.END}")
            print(f"  {Colors.CYAN}hashcat -m {most_likely['hashcat']} -a 0 hash.txt wordlist.txt -r rules/best64.rule{Colors.END}")
        if show_john and most_likely['john']:
            print(f"  {Colors.CYAN}john --format={most_likely['john']} hash.txt{Colors.END}")
            print(f"  {Colors.CYAN}john --format={most_likely['john']} --wordlist=wordlist.txt hash.txt{Colors.END}")

def process_file(input_file, output_file, hashcat_output, not_found, show_john, verbose):
    """Parse and identify hashes from a single file."""
    input_path = Path(input_file)
    
    if not input_path.is_file():
        print(f"\n{Colors.RED}File '{input_file}' not found!{Colors.END}")
        return
    
    hash_results = {}
    output_dir = Path('HashTag')
    output_dir.mkdir(exist_ok=True)
    
    if output_file:
        output_path = Path(output_file)
    else:
        output_path = output_dir / 'HashTag_Output_File.txt'
    
    print(f"\n{Colors.BOLD}Processing file:{Colors.END} {input_file}")
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                matches = identify_hash_advanced(line)
                hash_results[line] = matches
    
    hash_count = 0
    with open(output_path, 'w', encoding='utf-8') as out_f:
        for hash_str, matches in hash_results.items():
            if matches:
                hash_count += 1
                most_likely = matches[0]
                
                out_f.write(f'Hash: {hash_str}\n')
                out_f.write(f'Length: {len(hash_str)}\n')
                out_f.write(f'Most Likely: {most_likely["name"]}\n')
                if most_likely['hashcat']:
                    out_f.write(f'Hashcat Mode: {most_likely["hashcat"]}\n')
                if show_john and most_likely['john']:
                    out_f.write(f'John Format: {most_likely["john"]}\n')
                out_f.write(f'Confidence: {most_likely["priority"]}%\n')
                
                if len(matches) > 1:
                    other_types = [m['name'] for m in matches[1:]]
                    out_f.write(f'Other Possibilities: {", ".join(other_types)}\n')
                out_f.write('\n')
                
                if hashcat_output and most_likely['hashcat']:
                    mode_file = output_dir / f"mode_{most_likely['hashcat']}.txt"
                    with open(mode_file, 'a', encoding='utf-8') as mode_f:
                        mode_f.write(f'{hash_str}\n')
            elif not_found:
                out_f.write(f'Hash: {hash_str}\n')
                out_f.write(f'Length: {len(hash_str)}\n')
                out_f.write(f'Status: UNIDENTIFIED\n\n')
    
    print(f'\n{Colors.GREEN}Hashes Found:{Colors.END} {hash_count}')
    print(f'{Colors.GREEN}File successfully written:{Colors.END} {output_path}')
    
    type_counts = defaultdict(int)
    for matches in hash_results.values():
        if matches:
            type_counts[matches[0]['name']] += 1
    
    if type_counts and verbose:
        print(f"\n{Colors.BOLD}Hash Type Distribution:{Colors.END}")
        for hash_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {hash_type}: {count}")

def process_directory(input_dir, output_file, hashcat_output, threads, show_john, verbose):
    """Parse and identify hashes from directory with parallel processing."""
    input_path = Path(input_dir)
    
    if not input_path.is_dir():
        print(f"\n{Colors.RED}Directory '{input_dir}' not found!{Colors.END}")
        return
    
    output_dir = Path('HashTag')
    output_dir.mkdir(exist_ok=True)
    
    if output_file:
        output_path = Path(output_file)
    else:
        output_path = output_dir / 'HashTag_Hash_File.txt'
    
    valid_files = []
    
    print(f"\n{Colors.BOLD}Scanning directory:{Colors.END} {input_dir}")
    
    for root, _, filenames in os.walk(input_path):
        for filename in filenames:
            file_path = Path(root) / filename
            mime_type = mimetypes.guess_type(filename)[0]
            
            if mime_type == 'text/plain' or '.hash' in filename or '.txt' in filename:
                valid_files.append(file_path)
    
    print(f"{Colors.GREEN}Found {len(valid_files)} files to process{Colors.END}")
    
    valid_hashes = []
    
    def read_file(file_path):
        hashes = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and 3 < len(line) <= 500:
                        hashes.append(line)
        except Exception as e:
            print(f"{Colors.YELLOW}Error reading {file_path}: {e}{Colors.END}")
        return hashes
    
    print(f"\n{Colors.BOLD}Reading files with {threads} threads...{Colors.END}")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(read_file, f): f for f in valid_files}
        for future in as_completed(futures):
            valid_hashes.extend(future.result())
    
    if not valid_hashes:
        print(f'{Colors.RED}No valid hashes found.{Colors.END}')
        return
    
    seen = set()
    unique_hashes = []
    for h in valid_hashes:
        if h not in seen:
            seen.add(h)
            unique_hashes.append(h)
    
    print(f"\n{Colors.GREEN}Total Hashes:{Colors.END} {len(valid_hashes)}")
    print(f"{Colors.GREEN}Unique Hashes:{Colors.END} {len(unique_hashes)}")
    print(f"{Colors.BOLD}Identifying hashes...{Colors.END}\n")
    
    hash_results = {}
    notify_count = 0
    ten_percent = max(len(unique_hashes) // 10, 1)
    
    for hash_str in unique_hashes:
        matches = identify_hash_advanced(hash_str)
        hash_results[hash_str] = matches
        
        notify_count += 1
        if notify_count % ten_percent == 0:
            progress = (notify_count * 100) // len(unique_hashes)
            print(f'{Colors.CYAN}Progress: {progress}% ({notify_count}/{len(unique_hashes)}){Colors.END}')
    
    type_files = defaultdict(list)
    invalid_hashes = []
    
    for hash_str, matches in hash_results.items():
        if matches:
            most_likely = matches[0]
            type_files[most_likely['name']].append(hash_str)
        else:
            invalid_hashes.append(hash_str)
    
    print(f"\n{Colors.BOLD}Writing results...{Colors.END}")
    
    for hash_type, hashes in type_files.items():
        mode = None
        for pattern_group in HASH_PATTERNS:
            for ht in pattern_group['types']:
                if ht['name'] == hash_type:
                    mode = ht['hashcat']
                    break
            if mode:
                break
        
        if hashcat_output and mode:
            filename = f"{hash_type.replace('/', '_').replace(' ', '_')}_{mode}.txt"
        else:
            filename = f"{hash_type.replace('/', '_').replace(' ', '_')}.txt"
        
        type_file = output_dir / filename
        with open(type_file, 'w', encoding='utf-8') as f:
            for h in hashes:
                f.write(f'{h}\n')
    
    if invalid_hashes:
        invalid_file = output_dir / 'HashTag_Invalid_Hashes.txt'
        with open(invalid_file, 'w', encoding='utf-8') as f:
            for h in invalid_hashes:
                f.write(f'{h}\n')
    
    summary_file = output_dir / 'HashTag_Summary.txt'
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write('='*70 + '\n')
        f.write('HashTag Analysis Summary\n')
        f.write('='*70 + '\n\n')
        f.write(f'Total Files Scanned: {len(valid_files)}\n')
        f.write(f'Total Hashes Found: {len(valid_hashes)}\n')
        f.write(f'Unique Hashes: {len(unique_hashes)}\n')
        f.write(f'Identified Hashes: {len(unique_hashes) - len(invalid_hashes)}\n')
        f.write(f'Unidentified Hashes: {len(invalid_hashes)}\n\n')
        
        f.write('Hash Type Distribution:\n')
        f.write('-'*70 + '\n')
        for hash_type, hashes in sorted(type_files.items(), key=lambda x: len(x[1]), reverse=True):
            mode = None
            for pattern_group in HASH_PATTERNS:
                for ht in pattern_group['types']:
                    if ht['name'] == hash_type:
                        mode = ht['hashcat']
                        break
                if mode:
                    break
            
            mode_str = f"(Mode: {mode})" if mode else ""
            f.write(f'{hash_type} {mode_str}: {len(hashes)}\n')
    
    print(f'\n{Colors.BOLD}{Colors.GREEN}Analysis Complete!{Colors.END}')
    print(f'\n{Colors.BOLD}Summary:{Colors.END}')
    print(f'  Total Files: {len(valid_files)}')
    print(f'  Total Hashes: {len(valid_hashes)}')
    print(f'  Unique Hashes: {len(unique_hashes)}')
    print(f'  Identified: {len(unique_hashes) - len(invalid_hashes)}')
    print(f'  Unidentified: {len(invalid_hashes)}')
    
    if type_files:
        print(f'\n{Colors.BOLD}Top 10 Hash Types:{Colors.END}')
        for hash_type, hashes in sorted(type_files.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
            mode = None
            for pattern_group in HASH_PATTERNS:
                for ht in pattern_group['types']:
                    if ht['name'] == hash_type:
                        mode = ht['hashcat']
                        break
                if mode:
                    break
            mode_str = f"(Mode {mode})" if mode else ""
            print(f'  {hash_type} {mode_str}: {len(hashes)}')
    
    print(f'\n{Colors.GREEN}Results written to:{Colors.END} {output_dir}')
    print(f'{Colors.GREEN}Summary file:{Colors.END} {summary_file}')

def main():
    """Main entry point."""
    args = setup_parser()
    
    print(f'{Colors.BOLD}{Colors.HEADER}{"="*27}{Colors.END}')
    print(f'{Colors.BOLD}{Colors.HEADER}HashWizard by CyberPhvntom{Colors.END}')
    print(f'{Colors.BOLD}{Colors.HEADER}{"="*27}{Colors.END}\n')
    
    if args.singleHash:
        process_single_hash(args.singleHash, args.john, args.verbose, args.suggested, args.hashcatOutput)
    elif args.file:
        process_file(args.file, args.output, args.hashcatOutput, args.notFound, args.john, args.verbose)
    elif args.directory:
        process_directory(args.directory, args.output, args.hashcatOutput, args.threads, args.john, args.verbose)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f'\n\n{Colors.YELLOW}[!] Interrupted by user. Exiting...{Colors.END}')
        sys.exit(0)
    except Exception as e:
        print(f'\n{Colors.RED}[!] Error: {e}{Colors.END}')
        import traceback
        traceback.print_exc()

        sys.exit(1)











