Greylight
=========

Greylight is a lightweight greylisting daemon for Postfix, inspired by postgrey (https://postgrey.schweikert.ch/).  
It is written in C and designed to be simple, fast, and efficient.

Unlike heavier implementations, Greylight keeps its database in memory for maximum speed and persists it to SQLite to ensure consistency across restarts.  
The administrator can choose between pair (IP, sender) or triplet (IP, sender, recipient) as the greylisting key.

Features
--------

- Greylisting compatible with Postfix policy service
- Configurable key: pair or triplet
- In memory database with SQLite persistence
- Low CPU and memory usage
- Support for CIDR based whitelists (for example, large providers)
- Minimalistic implementation, easy to integrate

Installation
------------

1. Clone the repository:
   git clone https://github.com/andresmesi/greylight.git
   cd greylight

2. Build:
   gcc -O2 -Wall -std=gnu11 greylight.c -lsqlite3 -o greylight
   strip greylight

3. Install the binary:
   sudo cp greylight /usr/local/sbin/

Configuration
-------------

Postfix
-------

Edit main.cf and add:
   smtpd_recipient_restrictions =
       ...
       check_policy_service inet:127.0.0.1:10050
       ...

Greylight
---------

Run the daemon:
   /usr/local/sbin/greylight -p 10050 -d /var/lib/greylight/greylight.db

Options:
- -p <port>      Port for the policy service (default: 10050)
- -d <file>      Path to SQLite database file
- -m pair|triplet  Greylisting key mode
- -v             Verbose/debug mode

Database
--------

Greylight uses SQLite with the following basic tables:

- entries   greylisting records (IP, sender, recipient, timestamp)
- whitelist addresses or CIDR ranges to bypass greylisting

Roadmap
-------

- Native systemd support
- Usage statistics
- Admin API for whitelist and blacklist management

License
-------

This project is distributed under the MIT license.
