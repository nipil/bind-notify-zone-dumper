#!/usr/bin/env python3

import base64
import binascii
import dns.query
import dns.tsig
import dns.tsigkeyring
import dns.zone
import fcntl
import logging
import os.path
import queue
import re
import select
import subprocess
import sys
import threading
import time
import traceback

from systemd import journal


class Tsig:

    RE_NAME = r"^[-.A-Z0-9a-z]+$"

    def __init__(self, key_file):
        # load input
        self.key_file = os.path.expanduser(key_file)
        with open(self.key_file) as file_obj:
            key_name = file_obj.readline().rstrip('\n')
            key_secret_base64 = file_obj.readline().rstrip('\n')
            key_algo = file_obj.readline().rstrip('\n')

        # key name
        if len(key_name) == 0:
            raise Exception("Key name in key file '{0}' used for TSIG cannot be empty".format(self.key_file))
        if not re.fullmatch(self.RE_NAME, key_name):
            raise Exception("Invalid key name in key file '{0}'".format(self.key_file))
        self.key_name = key_name

        # key secret (base64 encoded)
        if len(key_secret_base64) == 0:
            raise Exception("Key secret in key file '{0}' used for TSIG cannot be empty".format(self.key_file))
        try:
            base64.b64decode(key_secret_base64, None, validate=True)
        except binascii.Error as e:
            raise Exception("Invalid base64 in secret in key file '{0}' used for TSIG".format(self.key_file))
        self.key_secret_base64 = key_secret_base64

        # key algo
        self.key_algo = getattr(dns.tsig, key_algo, None)
        if self.key_algo is None:
            raise Exception("Invalid algorithm {1} in key file '{0}' used for TSIG".format(self.key_file, key_algo))
        # actually load the dictionary
        self.key_ring = dns.tsigkeyring.from_text({
            self.key_name: self.key_secret_base64
        })

        logging.debug("{0}: name={1} secret={2} algo={3}".format(self.__class__.__name__, self.key_name, self.key_secret_base64, self.key_algo))

    def get_keyring(self):
        return self.key_ring

    def get_name(self):
        return self.key_name

    def get_algo(self):
        return self.key_algo


class ZoneInfo:

    # message filter information
    RE_NOTIFY=re.compile(r'zone ([^\s]+)/IN( \(signed\)|): sending notifies \(serial ([\d]+)\)$')
    RE_NOTIFY_ZONE=1
    RE_NOTIFY_DNSSEC=2
    RE_NOTIFY_SERIAL=3

    # increasing serial filtering
    LATEST_ZONE_INFO={}
    LATEST_ZONE_INFO_LOCK=threading.Lock()

    # TSIG
    TSIG = None
    TSIG_LOCK=threading.Lock()

    @classmethod
    def set_tsig(cls, tsig):
        cls.TSIG_LOCK.acquire()
        cls.TSIG = tsig
        cls.TSIG_LOCK.release()

    @classmethod
    def get_tsig(cls):
        cls.TSIG_LOCK.acquire()
        value = cls.TSIG
        cls.TSIG_LOCK.release()
        return value

    @classmethod
    def get_latest(cls, zone):
        cls.LATEST_ZONE_INFO_LOCK.acquire()
        value = cls.LATEST_ZONE_INFO.get(zone, None)
        cls.LATEST_ZONE_INFO_LOCK.release()
        return value

    @classmethod
    def set_latest(cls, zone, serial):
        cls.LATEST_ZONE_INFO_LOCK.acquire()
        cls.LATEST_ZONE_INFO[zone] = serial
        cls.LATEST_ZONE_INFO_LOCK.release()

    @classmethod
    def factory(cls, message):
        # filter and keep only notify message
        m = cls.RE_NOTIFY.search(message)
        if not m:
            # logging.debug("Message is not a notify : {0}".format(message))
            return None
        # extract information
        zone = m.group(1)
        dnssec = len(m.group(2)) > 0
        serial = int(m.group(3))
        # test serial
        latest = cls.get_latest(zone)
        if latest is not None and serial <= latest:
            logging.info("Discarding notify message for zone {0} with serial {1} (not newer than latest serial {2})".format(zone, serial, latest))
            return None
        # store requested serial
        cls.set_latest(zone, serial)
        # build and return
        zone_info = cls(zone, serial, dnssec)
        logging.info("Detected notification for zone {0} with serial {1}, with DNSSEC={2}".format(zone, serial, dnssec))
        return zone_info

    def __init__(self, name, serial, dnssec):
        self.name = name
        self.serial = serial
        self.dnssec = dnssec
        self.data = None
        self.saved_file_path = None
        self.output_dir_path = None

    def __repr__(self):
        return "ZoneInfo: name={0} serial={1} dnssec={2}".format(self.name, self.serial, self.dnssec)

    def update(self, server, key):
        tsig=self.get_tsig()
        # prepare query, returns a generator
        if tsig:
            dns_query = dns.query.xfr(server, self.name, keyring=tsig.get_keyring(), keyname=tsig.get_name(), keyalgorithm=tsig.get_algo())
        else:
            dns_query = dns.query.xfr(server, self.name)
        # transform the result, this triggering the request
        dns_zone = dns.zone.from_xfr(dns_query)
        # IMPORTANT: zone origin has a final . in its name !
        logging.debug("Zone origin: {0}".format(dns_zone.origin))
        # check soa records (there can be more than one)
        soa_rrset = dns_zone.find_rdataset("@", dns.rdatatype.SOA)
        if len(soa_rrset) == 0:
            logging.warn("No SOA record found for zone {0}, skipping".format(dns_zone.origin))
            return False
        # we use the first soa record to get serial
        serial = soa_rrset[0].serial
        logging.debug("Serial of fetched zone {0} is {1}".format(dns_zone.origin, serial))
        # get latest requested
        latest = self.get_latest(self.name)
        if latest:
            logging.debug("Latest serial for zone {0} is {1}".format(self.name, latest))
            if serial < latest:
                logging.warn("Ignoring fetched zone, as its serial {0} is older than latest known/requested {1}".format(serial, latest))
                return False
        # possibly update zone serial
        self.serial = serial
        # store zone content
        self.data = dns_zone.to_text()
        return True

    def get_data(self):
        return self.data

    def get_saved_file_path(self):
        return self.saved_file_path

    def set_saved_file_path(self, file_path):
        self.saved_file_path = file_path

    def set_output_dir_path(self, output_dir_path):
        self.output_dir_path = output_dir_path

    def get_output_dir_path(self):
        return self.output_dir_path


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

    def __init__(self, request_termination):
        # name
        self.__class__.COUNTER += 1
        super().__init__(name="{0}-{1}".format(self.__class__.__name__, self.__class__.COUNTER))
        # signaling
        self.request_termination = request_termination
        if self.request_termination is None:
            self.request_termination = threading.Event()

    def run(self):
        try:
            while not self.request_termination.is_set():
                # logging.debug("Iteration...")
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
        raise NotImplementedError("{0} must implement run_step (of {1})".format(self.__class__.__name__, TransformingThread.__name__))


class TransformingThread(BaseThread):

    def __init__(self, request_termination, in_queue, out_queue):
        super().__init__(request_termination)
        self.in_queue = in_queue
        self.out_queue = out_queue


class ProducingThread(BaseThread):

    def __init__(self, request_termination, out_queue):
        super().__init__(request_termination)
        self.out_queue = out_queue


class ConsumingThread(BaseThread):

    def __init__(self, request_termination, in_queue):
        super().__init__(request_termination)
        self.in_queue = in_queue


class ThreadPool:

    def __init__(self, cls, max_thread_count, request_termination, *args, **kwargs):
        # class of the threads to create
        self.cls = cls
        # signaling
        self.request_termination = request_termination
        if self.request_termination is None:
            self.request_termination = threading.Event()
        self.max_thread_count = max_thread_count
        # threads
        self.threads = [ cls(self.request_termination, *args, **kwargs) for i in range(self.max_thread_count) ]

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


class TransformingThreadPool(ThreadPool):

    def __init__(self, cls, max_thread_count, request_termination, in_queue, out_queue, *args, **kwargs):
        super().__init__(cls, max_thread_count, request_termination, in_queue, out_queue, *args, **kwargs)
        self.in_queue = in_queue
        self.out_queue = out_queue


class ProducingThreadPool(ThreadPool):

    def __init__(self, cls, max_thread_count, request_termination, out_queue, *args, **kwargs):
        super().__init__(cls, max_thread_count, request_termination, out_queue, *args, **kwargs)
        self.out_queue = out_queue


class ConsumingThreadPool(ThreadPool):

    def __init__(self, cls, max_thread_count, request_termination, in_queue, *args, **kwargs):
        super().__init__(cls, max_thread_count, request_termination, in_queue, *args, **kwargs)
        self.in_queue = in_queue


class MessageReaderThread(ProducingThread):

    def __init__(self, request_termination, out_queue):
        super().__init__(request_termination, out_queue)

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
        self.journal_events = self.journal.get_events()
        logging.debug("Using eventmask={0} for journal".format(self.journal_events))
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
        self.poller.register(self.journal.fileno(), self.journal_events)

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
            if eventmask & self.journal_events:
                self.read_messages()
            else:
                raise Exception("Error while polling from journal (event_mask={0})".format(eventmask))


class StdinReaderThread(MessageReaderThread):

    def __init__(self, request_termination, out_queue):
        super().__init__(request_termination, out_queue)
        stdin_fd = sys.stdin.fileno()
        # Create a poll object and register journal events on journal fd
        self.poller = select.poll()
        self.poller.register(stdin_fd, select.POLLIN | select.POLLPRI | select.POLLRDNORM | select.POLLRDBAND)
        # set stdin to non blocking
        stdin_flags = fcntl.fcntl(stdin_fd, fcntl.F_GETFL)
        fcntl.fcntl(stdin_fd, fcntl.F_SETFL, stdin_flags | os.O_NONBLOCK)
        # manage incomplete lines
        self.incomplete_line = ""

    def read_messages(self):
        first = True
        for message in sys.stdin.readlines():
            if message.endswith('\n'):
                message = message.rstrip('\n')
                # reintegrate previous incomplete lines
                if first:
                    logging.debug("Reintegrate previously unfinished line : {0}".format(self.incomplete_line))
                    first = False
                    message = self.incomplete_line + message
                    self.incomplete_line = ""
                logging.debug("Complete line : {0}".format(message))
                self.process_message(message)
            else:
                logging.debug("Incomplete line added to buffer : {0}".format(message))
                self.incomplete_line += message
                logging.debug("Incomplete line buffer contains : {0}".format(self.incomplete_line))

    def run_step(self):
        events = self.poller.poll(self.get_default_timeout_ms())
        for fd, eventmask in events:
            logging.debug("Eventmask {1} on file descriptor {0}".format(fd, eventmask))
            if eventmask & (select.POLLIN | select.POLLPRI):
                self.read_messages()
            elif eventmask & select.POLLHUP:
                logging.info("Exiting due to HUP on STDIN (end of pipe)")
                self.request_termination.set()
            else:
                raise Exception("Error while polling from STDIN (event_mask={0})".format(eventmask))


class FileReaderThread(MessageReaderThread):

    def __init__(self, request_termination, out_queue, file_path, error_notification_interval_seconds):
        super().__init__(request_termination, out_queue)
        self.previous_file_length = None
        self.file_path = os.path.expanduser(file_path)
        self.next_error_notification_time = None
        logging.info("Only one file-related error per {0} seconds will be reported".format(error_notification_interval_seconds))
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


class ZoneTransferThread(TransformingThread):

    def __init__(self, request_termination, in_queue, out_queue, server):
        super().__init__(request_termination, in_queue, out_queue)
        self.server = server

    def run_step(self):
        # get an item to process
        try:
            zone_info = self.in_queue.get(True, self.get_default_timeout_sec())
        except queue.Empty as e:
            return
        # mark item as done
        self.in_queue.task_done()
        # does a zone transfer and update object
        logging.info("Transfering zone {0} and expecting serial {1}".format(zone_info.name, zone_info.serial))
        try:
            if zone_info.update(self.server, None):
                self.out_queue.put(zone_info)
        except dns.exception.DNSException as e:
            # No answer or RRset not for qname
            logging.error("Problem while doing zone transfer for '{0}': {1}".format(zone_info.name, e))
            # enhanced debugging output
            if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
                traceback.print_exc(file=sys.stdout)


class ZoneWriterThread(TransformingThread):

    def __init__(self, request_termination, in_queue, out_queue, output_dir_path):
        super().__init__(request_termination, in_queue, out_queue)
        self.output_dir_path = os.path.expanduser(output_dir_path)

    def store(self, zone_info):
        target_directory = os.path.join(self.output_dir_path, zone_info.name)
        target_file = os.path.join(target_directory, str(zone_info.serial))
        logging.info("Saving '{0}'".format(target_file))
        os.makedirs(target_directory, exist_ok=True)
        with open(target_file, 'wb') as file_obj:
            file_obj.write(zone_info.get_data())
        zone_info.set_saved_file_path(target_file)
        zone_info.set_output_dir_path(self.output_dir_path)

    def run_step(self):
        # get an item to process
        try:
            zone_info = self.in_queue.get(True, self.get_default_timeout_sec())
        except queue.Empty as e:
            return
        # mark item as done
        self.in_queue.task_done()
        # save zone in archives
        self.store(zone_info)
        # forward
        self.out_queue.put(zone_info)

class PostProcessingThread(ConsumingThread):

    def __init__(self, request_termination, in_queue, external_command, external_timeout, external_mute):
        super().__init__(request_termination, in_queue)
        self.external_command = external_command
        self.external_timeout = external_timeout
        self.external_mute = external_mute

    def run_command(self, zone_info):
        # input/output
        if self.external_mute:
            stream = subprocess.DEVNULL
        else:
            stream = None
        # exec
        command = "{0} {1} {2} {3} {4}".format(self.external_command, zone_info.get_output_dir_path(), zone_info.get_saved_file_path(), zone_info.name, zone_info.serial)
        logging.debug("Running command with timeout {0} : {1}".format(self.external_timeout, command))
        result = subprocess.run(command, timeout=self.external_timeout, shell=True, stdin=stream, stdout=stream, stderr=stream)
        # result
        message = "Post-processing command returned with code {0}".format(result.returncode)
        if result.returncode == 0:
            logging.info(message)
        else:
            logging.warn(message)

    def run_step(self):
        # get an item to process
        try:
            zone_info = self.in_queue.get(True, self.get_default_timeout_sec())
        except queue.Empty as e:
            return
        # mark item as done
        self.in_queue.task_done()
        # run post-process if requested
        if self.external_command:
            try:
                self.run_command(zone_info)
            except subprocess.SubprocessError as e:
                logging.error("{0}: {1}".format(e.__class__.__name__, e))
                # enhanced debugging output
                if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
                    traceback.print_exc(file=sys.stdout)


if __name__ == '__main__':

    import argparse
    import signal

    # global exit flag
    request_termination = threading.Event()

    # signal handler
    def handler(signum, frame):
        logging.info("Receiving signal {0}, requesting exit...".format(signum))
        request_termination.set()

    # Hangup detected on controlling terminal or death of controlling process
    signal.signal(signal.SIGHUP, handler)
    # Kill signal
    signal.signal(signal.SIGUSR1, handler)
    # User-defined signal 2
    signal.signal(signal.SIGUSR2, handler)
    # Broken pipe: write to pipe with no readers
    signal.signal(signal.SIGPIPE, handler)
    # Termination signal
    signal.signal(signal.SIGTERM, handler)

    # parse arguments
    try:
        # analyze commande line arguments
        parser = argparse.ArgumentParser(description="Bind9 notify zone dumper")
        parser.add_argument("-j", "--journald", metavar="SPEC", type=str, nargs="*", help="read from journald unit")
        parser.add_argument("-f", "--file", metavar="FILE", type=str, help="read from file")
        parser.add_argument("-l", "--log-level", metavar="LVL", choices=["critical", "error", "warning", "info", "debug"], default="warning")
        parser.add_argument("-p", "--polling", metavar="MS", type=int, help="polling interval in milliseconds", default=1000)
        parser.add_argument("-k", "--key", metavar="KEY", type=str, help="key file to use for TSIG")
        parser.add_argument("-z", "--zone-threads", metavar="N", type=int, help="number of zone transfer threads", default=1)
        parser.add_argument("-e", "--external-threads", metavar="M", type=int, help="number of threads for external post-processing", default=1)
        parser.add_argument("-c", "--external-command", metavar="CMD", type=str, help="program to run after a zone has been processed")
        parser.add_argument("-t", "--external-timeout", metavar="SEC", type=int, help="timeout after which the external command is killed (in seconds)", default=10)
        parser.add_argument("-m", "--external-mute", action="store_true", help="shut stdin/stdout/sterr of external command")
        parser.add_argument("-s", "--server", metavar="HOST", type=str, help="dns server to transfer zones from", default="localhost")
        parser.add_argument("-d", "--destination", metavar="DST", type=str, help="folder where zone data are stored", default="zones")

        args = parser.parse_args()

        # configure logging
        numeric_level = getattr(logging, args.log_level.upper())
        logging.basicConfig(format='%(asctime)s %(threadName)s %(levelname)s %(message)s', level=numeric_level)
        logging.debug("Command line arguments: {0}".format(args))

        # load key for tsig
        if args.key:
            ZoneInfo.set_tsig(Tsig(args.key))

        # check mutually exclusive settings
        if args.file is not None and args.journald is not None:
            logging.error("Cannot use journald input and file input at the same time")
            sys.exit(1)

        # define default polling timeout
        BaseThread.set_default_timeout_ms(args.polling)

        # input message queue
        producer_queue = queue.Queue()
        transfer_queue = queue.Queue()
        postprocess_queue = queue.Queue()

        # select input
        if args.journald is not None:
            logging.info("Reading from systemd journal")
            reader_thread = JournalReaderThread(request_termination, producer_queue, args.journald)
        elif args.file is not None:
            logging.info("Reading from file '{0}'".format(args.file))
            reader_thread = FileReaderThread(request_termination, producer_queue, args.file)
        else:
            logging.info("Reading from standard input (stdin)")
            reader_thread = StdinReaderThread(request_termination, producer_queue)

        # create dns threads
        ztt_pool = TransformingThreadPool(ZoneTransferThread, args.zone_threads, request_termination, producer_queue, transfer_queue, args.server)

        # create writer thread
        writer = ZoneWriterThread(request_termination, transfer_queue, postprocess_queue, args.destination)

        # create post-processor threads
        ppt_pool = ConsumingThreadPool(PostProcessingThread, args.external_threads, request_termination, postprocess_queue, args.external_command, args.external_timeout, args.external_mute)

        # start/stop threads
        with ppt_pool, writer, ztt_pool, reader_thread:
            try:
                while not request_termination.wait(BaseThread.get_default_timeout_ms()):
                    pass
            except KeyboardInterrupt as e:
                logging.warning("Exiting due to keyboard interrupt (Ctrl-C = SIGINT)")

        # input message queue
        logging.info("Tasks left in queues : {0} notifications, {1} transfers and {2} saves were discarded".format(producer_queue.qsize(), transfer_queue.qsize(), postprocess_queue.qsize()))

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
