# bind-notify-zone-dumper

Whenever a bind9 zone notification is detected in the source feed, fetch zone content and archives it to disk

# install

    sudo apt-get install python3-venv build-essential libsystemd-dev

    git clone https://github.com/nipil/bind-notify-zone-dumper.git
    cd bind-notify-zone-dumper

    python3 -m venv venv
    venv/bin/pip install -r requirements.txt

# run

    /path/to/bind-notify-zone-dumper/{venv/bin/python3,bnzd.py} [options]

# options

    usage: bnzd.py [-h] [-j [SPEC [SPEC ...]]] [-f FILE] [-l LVL]
                   [-p MS] [-k KEY] [-z N] [-s HOST] [-d DST]
                   [-e M] [-c CMD] [-t SEC] [-m]

    Bind9 notify zone dumper

    optional arguments:
        -h, --help            show this help message and exit

        -s HOST
        --server HOST
            dns server to transfer zones from
            Default: localhost

        -d DST
        --destination DST
            folder where zone data are stored
            Default: zones

        -j [SPEC [SPEC ...]]
        --journald [SPEC [SPEC ...]]
            read from journald unit
            use SPEC for filtering (see examples)

        -f FILE
        --file FILE
            read from file

        -p MS
        --polling MS
            polling interval in milliseconds
            Default: 1000 ms

        -k KEY
        --key KEY
            key file to use for TSIG

        -z N
        --zone-threads N
            number of zone transfer threads
            Default: 1

        -e M
        --external-threads M
            number of threads for external post-processing
            Default: 1

        -c CMD
        --external-command CMD
            program to run after a zone has been processed
            arg1: saved zone file
            arg2: zone name
            arg3: zone serial

        -t SEC
        --external-timeout SEC
            timeout after which the external command is killed (in secs)
            Default: 10

        -m, --external-mute
            shut stdin/stdout/sterr when running external command
            if absent, command uses parent configuration

# parallelism

The program is fully asynchronous and non-blocking, polling inputs and queues

There are a few threads :

- the main thread does the initialization, waits then does teardown
- there is 1 reader thread
- there are `-z` dns threads
- there is 1 saving thread
- there are `-e` post-processing threads

And some processes :

- post-processing threads spawn a temporary process when executing command

# examples

## input

Input defaults to stdin.

If `-j` is provided, get events from systemd-journald instead (see below)

If `-f` is provided, poll given file for modifications instead

To read from (unfiltered) systemd-journald :

    ./bnzd.py -j

You can filter journald entries (to lighten the load on busy servers)

- see `man systemd.journal-fields` for selectors
- see `journalctl -f -o json` for for samples
- useful selectors : `_SYSTEMD_UNIT`, `SYSLOG_IDENTIFIER`, `_COMM`

To read from systemd-journald, filtering on unit and command :

    ./bnzd.py -j _SYSTEMD_UNIT=bind9.service _COMM=named

## post-process command

To run a given command after every zone save, use `-c` :

    ./bnzd.py ... -c /path/to/script ARG1 ARG2 ARG3

The following arguments are provided :

- ARG1 : saved zone file path (including `--destination`)
- ARG2 : zone name
- ARG3 : saved zone serial

Remark:

- by default, the invoked script reads and outputs to the same pipes as the parent process (this script)
- to silence sub-process output, use the `-m` option
- you can safely silence the sub-process, as its return code is still logged (at level info if zero, else at level warning)

A watchdog is configured (`-t`) to kill process lasting too long, adapt it for longer commands.

## key file

A key file is necessary when speaking to servers requiring it.

Key file format :

- first line : key name
- second line : key secret (base64)
- third line : key algorithm (see [dns.tsig, section 'Variable', `HMAC_*`](http://www.dnspython.org/docs/1.15.0/dns.tsig-module.html))

# triggers

Only message folloing the syntax below will trigger an action :

    zone example.com/IN: sending notifies (serial 193)
    zone example.org/IN (signed): sending notifies (serial 323)
