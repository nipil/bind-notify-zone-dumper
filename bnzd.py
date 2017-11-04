#!/usr/bin/env python3

import logging
import os.path
import queue
import re
import select
import sys
import threading
import time
import traceback

from systemd import journal

class ZoneInfo:

    # message filter information
    RE_NOTIFY=re.compile(r'^zone ([^\s]+)/IN( \(signed\)|): sending notifies \(serial ([\d]+)\)$')
    RE_NOTIFY_ZONE=1
    RE_NOTIFY_DNSSEC=2
    RE_NOTIFY_SERIAL=3

    # increasing serial filtering
    LATEST_ZONE_INFO={}

    @classmethod
    def factory(cls, message):
        # filter and keep only notify message
        m = cls.RE_NOTIFY.fullmatch(message)
        if not m:
            # logging.debug("Message is not a notify : {0}".format(message))
            return None
        # extract information
        zone = m.group(1)
        dnssec = len(m.group(2)) > 0
        serial = int(m.group(3))
        # test serial
        latest = cls.LATEST_ZONE_INFO.get(zone, None)
        if latest is not None and serial <= latest:
            logging.info("Discarding notify message for zone {0} with serial {1} (not newer than latest serial {2})".format(zone, serial, latest))
            return None
        cls.LATEST_ZONE_INFO[zone] = serial
        # build and return
        zone_info = cls(zone, serial, dnssec)
        logging.info("Detected notification for zone {0} with serial {1}, with DNSSEC={2}".format(zone, serial, dnssec))
        return zone_info

    def __init__(self, name, serial, dnssec):
        self.name = name
        self.serial = serial
        self.dnssec = dnssec

    def __repr__(self):
        return "ZoneInfo: name={0} serial={1} dnssec={2}".format(self.name, self.serial, self.dnssec)

class BaseThread(threading.Thread):

    COUNTER=0

    DEFAULT_POLLING_TIMEOUT_MS=None

    @classmethod
    def set_default_timeout_ms(cls, timeout_ms):
        cls.DEFAULT_POLLING_TIMEOUT_MS = timeout_ms

    @classmethod
    def get_default_timeout_ms(cls):
        return cls.DEFAULT_POLLING_TIMEOUT_MS

    @classmethod
    def get_default_timeout_sec(cls):
        return cls.DEFAULT_POLLING_TIMEOUT_MS / 1000

    def __init__(self, request_termination, in_queue, out_queue):
        # name
        self.__class__.COUNTER += 1
        super().__init__(name="{0}-{1}".format(self.__class__.__name__, self.__class__.COUNTER))
        # signaling
        self.request_termination = request_termination
        if self.request_termination is None:
            self.request_termination = threading.Event()
        # processing
        self.in_queue = in_queue
        self.out_queue = out_queue

    def run(self):
        try:
            while not self.request_termination.is_set():
                self.run_step()
        except Exception as e:
            logging.critical("{0}: {1}".format(e.__class__.__name__, e))
            # enhanced debugging output
            if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
                traceback.print_exc(file=sys.stdout)
        finally:
            self.request_termination.set()
        logging.debug("Exiting thread {0}".format(self.name))

    def __enter__(self):
        logging.debug("Starting {0} thread".format(self.name))
        self.start()

    def __exit__(self, exc_type, exc_value, traceback):
        self.request_termination.set()
        logging.info("Waiting for thread {0} to finish...".format(self.name))
        self.join()
        logging.debug("Thread {0} finished.".format(self.name))

    def run_step(self):
        raise NotImplementedError("{0} must implement run_step (of {1})".format(self.__class__.__name__, BaseThread.__name__))

class ThreadPool:

    def __init__(self, cls, request_termination, in_queue, out_queue, max_thread_count):
        self.cls = cls
        # signaling
        self.request_termination = request_termination
        if self.request_termination is None:
            self.request_termination = threading.Event()
        # processing
        self.in_queue = in_queue
        self.out_queue = out_queue
        self.max_thread_count = max_thread_count
        # threads
        self.threads = [ cls(self.request_termination, self.in_queue, self.out_queue) for i in range(self.max_thread_count) ]

    def __enter__(self):
        logging.debug("Starting pool of {0} {1}".format(self.max_thread_count, self.cls.__name__))
        for thread in self.threads:
            thread.start()
        logging.debug("Threads {0} started".format([ t.name for t in self.threads]))

    def __exit__(self, exc_type, exc_value, traceback):
        logging.debug("{0}({1}) exited with ({2}, {3}, {4})".format(self.__class__.__name__, self.cls.__name__, exc_type, exc_value, traceback))
        # signal threads that they should stop
        self.request_termination.set()
        # wait for thread completion
        logging.info("Waiting for threads {0} to finish...".format([ t.name for t in self.threads]))
        for thread in self.threads:
            thread.join()
        logging.debug("Threads {0} finished".format([ t.name for t in self.threads]))

class MessageReaderThread(BaseThread):

    def __init__(self, request_termination, out_queue):
        super().__init__(request_termination, None, out_queue)

    def process_message(self, message):
        # only queue notify messages
        zone_info = ZoneInfo.factory(message)
        if zone_info:
            self.out_queue.put(zone_info)

class JournalReaderThread(MessageReaderThread):

    def __init__(self, request_termination, out_queue, filters):
        super().__init__(request_termination, out_queue)
        logging.debug("Journal filters: {0}".format(filters))
        self.journal = journal.Reader()
        logging.debug("Journal file descriptor is {0}".format(self.journal.fileno()))
        # add filters
        for filt in filters:
            try:
                self.journal.add_match(filt)
            except ValueError as e:
                raise Exception("{2}.add_match failed for '{1}' : {0}. See `man systemd.journal-fields` for syntax and valid fields.".format(e, filt, journal.__name__))
        # Move to the end of the journal
        self.journal.seek_tail()
        # Important! - Discard old journal entries
        self.journal.get_previous()
        # Create a poll object and register journal events on journal fd
        self.poller = select.poll()
        self.poller.register(self.journal.fileno(), self.journal.get_events())

    def read_messages(self):
        # Process events and reset the readable state of the file descriptor returned by .fileno()
        # Will return constants:
        # - NOP if no change
        # - APPEND if new entries have been added to the end of the journal
        # - INVALIDATE if journal files have been added or removed
        process_result = self.journal.process()
        logging.debug("Journal process returned {0}".format(process_result))

        # feed the message to the following blocks
        count_message = 0
        for entry in self.journal:
            count_message += 1
            self.process_message(entry["MESSAGE"])
        logging.debug("Processed {0} journal entries".format(count_message))

    def run_step(self):
        events = self.poller.poll(self.get_default_timeout_ms())
        for fd, eventmask in events:
            logging.debug("Eventmask {1} on file descriptor {0}".format(fd, eventmask))
            if eventmask & (select.POLLIN | select.POLLPRI):
                self.read_messages()
            else:
                raise Exception("Error while polling from journal (event_mask={0})".format(eventmask))

class StdinReaderThread(MessageReaderThread):

    def __init__(self, request_termination, out_queue):
        super().__init__(request_termination, out_queue)
        # Create a poll object and register journal events on journal fd
        self.poller = select.poll()
        self.poller.register(sys.stdin, select.POLLIN | select.POLLPRI)

    def read_messages(self):
        # get message and handle EOF
        try:
            message = input()
        except EOFError as e:
            logging.info("Exiting due to EOF on STDIN (Ctrl-D)")
            sys.exit(0)
        # process message
        self.process_message(message)

    def run_step(self):
        events = self.poller.poll(self.get_default_timeout_ms())
        for fd, eventmask in events:
            logging.debug("Eventmask {1} on file descriptor {0}".format(fd, eventmask))
            if eventmask & (select.POLLIN | select.POLLPRI):
                self.read_messages()
            else:
                raise Exception("Error while polling from journal (event_mask={0})".format(eventmask))

class FileReaderThread(MessageReaderThread):

    def __init__(self, request_termination, out_queue, file_path, error_notification_interval_seconds=60):
        super().__init__(request_termination, out_queue)
        self.previous_file_length = None
        self.file_path = os.path.expanduser(file_path)
        self.next_error_notification_time = None
        self.error_notification_interval_seconds = error_notification_interval_seconds

    def read_messages(self, file_obj):
        # fetch end and read file size
        file_size = file_obj.seek(0, 2)
        # if first run, only get file length
        if self.previous_file_length is None:
            self.previous_file_length = file_size
            logging.info("Starting watching file '{0}' at offset {1}".format(self.file_path, self.previous_file_length))
            return
        # if size did not change, consider it's the same content
        if self.previous_file_length == file_size:
            logging.debug("File size of '{0}' is {1} and did not change since last poll".format(self.file_path, self.previous_file_length))
            return
        # if size decreased, truncation occured
        if self.previous_file_length > file_size:
            logging.info("File size of '{0}' decreased from {1} to {2}, restarting (truncation detected)".format(self.file_path, self.previous_file_length, file_size))
            self.previous_file_length = 0
        # if size increased, there is new content
        if self.previous_file_length < file_size:
            logging.debug("File size of '{0}' increased from {1} to {2} ({3} new bytes)".format(self.file_path, self.previous_file_length, file_size, file_size - self.previous_file_length))
        # go to previous position and read everything
        file_obj.seek(self.previous_file_length)
        # read a potential line
        line = file_obj.readline()
        while line:
            if line.endswith('\n'):
                logging.debug("Complete line '{0}'".format(line))
                self.process_message(line.rstrip('\n'))
                self.previous_file_length = file_obj.tell()
                line = file_obj.readline()
            else:
                logging.debug("Unfinished line '{0}'".format(line))
                file_obj.seek(self.previous_file_length)
                break

    def run_step(self):
        time.sleep(self.get_default_timeout_sec())
        try:
            with open(self.file_path) as file_obj:
                self.read_messages(file_obj)
        except OSError as e:
            current_time = time.time()
            if self.next_error_notification_time is None or self.next_error_notification_time < current_time:
                logging.error("{0}: {1}".format(e.__class__.__name__, e))
                self.next_error_notification_time = current_time + self.error_notification_interval_seconds


class ZoneTransferThread(BaseThread):

    def __init__(self, request_termination, in_queue, out_queue):
        super().__init__(request_termination, in_queue, out_queue)

    def run_step(self):
        time.sleep(self.get_default_timeout_sec())
        logging.debug("Iteration...")

if __name__ == '__main__':

    import argparse

    try:
        # analyze commande line arguments
        parser = argparse.ArgumentParser(description="Bind9 notify zone dumper")
        parser.add_argument("-j", "--journald", metavar="SPEC", type=str, nargs="*", help="read from journald unit")
        parser.add_argument("-f", "--file", metavar="FILE", type=str, help="read from file")
        parser.add_argument("-l", "--log-level", metavar="LVL", choices=["critical", "error", "warning", "info", "debug"], default="warning")
        parser.add_argument("-p", "--polling", metavar="MS", type=int, help="polling interval in milliseconds", default=1000)
        parser.add_argument("-z", "--zone-threads", metavar="R", type=int, help="number of zone transfer threads", default=1)
        args = parser.parse_args()

        # configure logging
        numeric_level = getattr(logging, args.log_level.upper())
        logging.basicConfig(format='%(asctime)s %(threadName)s %(levelname)s %(message)s', level=numeric_level)
        logging.debug("Command line arguments: {0}".format(args))

        # check mutually exclusive settings
        if args.file is not None and args.journald is not None:
            logging.error("Cannot use journald input and file input at the same time")
            sys.exit(1)

        # define default polling timeout
        BaseThread.set_default_timeout_ms(args.polling)

        # global exit flag
        request_termination = threading.Event()

        # input message queue
        zone_info_queue = queue.Queue()
        zone_data_queue = queue.Queue()

        # select input
        if args.journald is not None:
            logging.info("Reading from systemd journal")
            reader_thread = JournalReaderThread(request_termination, zone_info_queue, args.journald)
        elif args.file is not None:
            logging.info("Reading from file '{0}'".format(args.file))
            reader_thread = FileReaderThread(request_termination, zone_info_queue, args.file)
        else:
            logging.info("Reading from standard input (stdin)")
            reader_thread = StdinReaderThread(request_termination, zone_info_queue)

        # create working threads
        ztt_pool = ThreadPool(ZoneTransferThread, request_termination, zone_info_queue, zone_data_queue, args.zone_threads)

        # start/stop threads and enter main loop
        with ztt_pool:
            with reader_thread:
                try:
                    while not request_termination.wait(BaseThread.get_default_timeout_ms()):
                        pass
                except KeyboardInterrupt as e:
                    logging.warning("Exiting due to keyboard interrupt (Ctrl-C = SIGINT)")

        # clean exit
        sys.exit(0)

    except SystemExit as e:
        message = "Exiting with return code {0}".format(e.code)
        if e.code == 0:
            logging.info(message)
        else:
            logging.warn(message)
            raise e

    except Exception as e:
        logging.critical("{0}: {1}".format(e.__class__.__name__, e))
        # when debugging, we want the stack-trace
        if args.log_level == "debug":
            raise e