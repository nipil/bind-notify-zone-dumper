# bind-notify-zone-dumper

Whenever a bind9 zone notification is detected in the source feed, fetch zone content and archives it to disk

# install

    sudo apt-get install python3-venv build-essential libsystemd-dev pkg-config python3-dev

    git clone https://github.com/nipil/bind-notify-zone-dumper.git
    cd bind-notify-zone-dumper

    python3 -m venv venv
    venv/bin/pip install -r requirements.txt

# run

    /path/to/bind-notify-zone-dumper/{venv/bin/python3,bnzd.py} [options]

# options

    usage: bnzd.py [-h] [-j [SPEC [SPEC ...]]] [-f FILE] [-l LVL]
                   [-p MS] [-k KEY] [-z N] [-s HOST] [-d DST]
                   [-e M] [-c CMD] [-t SEC] [-m] [--syslog [TARGET]]

    Bind9 notify zone dumper

    optional arguments:
        -h, --help            show this help message and exit

        -l LVL
        --log-level LVL
            default logging level (debug, info, warn, error...)
            defaults to "warn"
            if "debug", each message is prefixed with additionnal info

        --syslog [TARGET]
            logs to syslog instead of stderr
            TARGET defaults to '/dev/log' (syslog's unix socket input)
            set TARGET to hostname:udpport to log on a networked syslog

        --server HOST
            dns server to transfer zones from
            Default: localhost

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

# how to run

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

- ARG1 : destination directory (from `--destination`)
- ARG2 : saved zone file path (including `--destination`)
- ARG3 : zone name
- ARG4 : saved zone serial

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

# example setup

This is how i use it on my own production master servers :-)

First, required install system packages (see top of this document)

Then, define install paths :

    export BNZD_USER=bnzd
    export BNZD_DATA=/var/lib/${BNZD_USER}
    export BNZD_BIN=/opt/${BNZD_USER}

Optionally, clean workspace :

    rm -Rf ${BNZD_DATA} ${BNZD_BIN}

If not already done, create an unpriviledged system user and allow him to read journal :

    useradd --system ${BNZD_USER}
    gpasswd -a bnzd systemd-journal

Then, as root, create its working space :

    mkdir ${BNZD_DATA}
    git -C ${BNZD_DATA} init
    git -C ${BNZD_DATA} config user.name "${BNZD_USER}"
    git -C ${BNZD_DATA} config user.email "${BNZD_USER}@localhost"

If you are using TSIG for zone transfer, configure it first :

    export TSIG_NAME='key-name'
    export TSIG_SECRET='key-secret-in-base64'
    export TSIG_ALGO='key-algo'

Install TSIG key :

    echo -e "${TSIG_NAME}\n${TSIG_SECRET}\n${TSIG_ALGO}" > ${BNZD_DATA}/tsig.key
    chmod 600 ${BNZD_DATA}/tsig.key

Finalize permissions

    chown -R ${BNZD_USER}:${BNZD_USER} ${BNZD_DATA}

Continue with software installation :

    git clone https://github.com/nipil/bind-notify-zone-dumper.git ${BNZD_BIN}
    python3 -m venv ${BNZD_BIN}/venv
    ${BNZD_BIN}/venv/bin/pip install -r ${BNZD_BIN}/requirements.txt

Install a systemd service unit (remove `-k` if you do not use it) :

    cat << EOF > /etc/systemd/system/${BNZD_USER}.service
    [Unit]
    Description=bind-notify-zone-dumper
    Wants=bind9.service

    [Service]
    User=${BNZD_USER}
    Group=${BNZD_USER}
    Restart=on-failure
    ExecStart=${BNZD_BIN}/venv/bin/python3 ${BNZD_BIN}/bnzd.py -d ${BNZD_DATA} -l info --syslog -j _SYSTEMD_UNIT=bind9.service -k ${BNZD_DATA}/tsig.key -m -c ${BNZD_BIN}/tools/git-commit-hook.sh

    [Install]
    WantedBy=multi-user.target
    EOF

Note: you can use `always` instead of `on-failure` to keep it running.

Then reload `systemd` config to detect new unit :

    systemctl daemon-reload
    systemctl status bnzd

Start the process :

    systemctl start bnzd
    systemctl status bnzd

Stop the process :

    systemctl stop bnzd

If everything is ok, enable the service :

    systemctl enable bnzd

Finally, restart server to ensure that it is started at startup.
