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

# triggers

    zone example.com/IN: sending notifies (serial 193)
    zone example.org/IN (signed): sending notifies (serial 323)
