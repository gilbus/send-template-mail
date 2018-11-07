#!/usr/bin/env python3
"""
Send mails to an unlimited number people specified inside a csv file with a
template in which you can use any variables of the csv row. Attachments can be included
as well. Additionally you can pass any amount of filter for any csv attribute, e.g. if
the male students should receive a different mail than the female ones.
The script will ask you for your smtp password. Pass any file via `@` to tread its
content as additional arguments to this script, i.e. `... @smtp_args.txt -e ...`
(requires --long-option=value format). See README.md for more information.
"""

# this standard lib is awesome *__*
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, FileType
from getpass import getpass, getuser
from csv import DictReader, Error as csv_error
from string import Template
from smtplib import SMTP, SMTPException, SMTPAuthenticationError
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart

try:
    from typing import Union, Set
except ImportError:
    # In case the lowest supported version (3.4) is used but the python(3)-typing
    # package is not installed
    # Not necessary for runtime and hopefully development takes place with a current
    # python version ;)
    pass
from os.path import sep, abspath, realpath
from re import match
from sys import stderr, argv
from pathlib import Path
from hashlib import md5 as md5_
from datetime import datetime
import logging

__author__ = "gilbus"
__license__ = "GPL v3"

# see https://docs.python.org/3/library/logging.html#logrecord-attributes
_logging_format = "%(asctime)s:%(levelname)s:%(message)s"
# see https://docs.python.org/3/library/time.html?highlight=strftime#time.strftime
_date_format = "%Y-%m-%d %H:%M:%S"


def now() -> str:
    return datetime.now().strftime(_date_format)


def md5(text: str) -> str:
    m = md5_()
    m.update(text.encode())
    return m.hexdigest()


def main() -> int:

    main_parser = ArgumentParser(
        description=__doc__,
        formatter_class=ArgumentDefaultsHelpFormatter,
        epilog="{} {}, remember `@arg_file` (see description above)".format(
            __author__, __license__
        ),
        fromfile_prefix_chars="@",
    )

    main_parser.add_argument(
        "csv_file",
        type=FileType(),
        help="""CSV file with a header line containing containing the entries. The
        header names can be used inside the template to personalize the messages. Use
        `-` for STDIN.""",
    )
    main_parser.add_argument("subject", type=str, help="Subject of the message")
    main_parser.add_argument(
        "template_file",
        type=FileType(),
        help="""Template file for the body of the message. Variables to replace must be
        specified via `${variable}`.""",
    )
    main_parser.add_argument(
        "--hash-file",
        type=Path,
        help="""For every processed mail address write its md5-hash to this file.
        Subsequent runs of this script (with this file passed again) will skip any mail
        address if its hash is inside the file. Lines starting with a `#` are ignored
        and used to write timestamps.""",
    )
    main_parser.add_argument(
        "--no-update",
        action="store_true",
        help="Do not add any hash entries to the `hash-file`",
    )
    mail_args_parser = main_parser.add_argument_group(
        "Email Arguments",
        """Use this arguments to change the header information of the mail, e.g. set
        From: "Jane Doe <jane.doe@example.com".""",
    )
    mail_args_parser.add_argument(
        "-f",
        "--from_",
        default=getuser(),
        help="The `From:` to show inside the mail. Supports `Name <address>` format.",
    )
    mail_args_parser.add_argument(
        "-r", "--reply-to", type=str, help="Reply-To address to set"
    )
    mail_args_parser.add_argument(
        "-a",
        "--attachment",
        # files must be opened and read in binary mode
        type=FileType(mode="br"),
        nargs="+",
        help="Attachments to append to the mail.",
    )
    csv_args_parser = main_parser.add_argument_group(
        "CSV Arguments",
        """Use this arguments to modify the processing of the rows inside the given CSV
        file. In 2018 all female students received a slightly different mail containing
        a flyer for the `movement` mentoring project. You can use the filters for this
        functionality.""",
    )
    csv_args_parser.add_argument(
        "-e",
        "--email-field",
        type=str,
        help="The header of the entry containing the address to send the mail to.",
        default="mail",
    )
    csv_args_parser.add_argument(
        "--filter",
        metavar=("'Field header'", "'RegEx'"),
        nargs=2,
        help="""Filter to apply to the specified field of any entry. Entries
        evaluating to false are skipped. Can be specified multiple times. Use single
        dashes to prevent your shell from expanding *.""",
        action="append",
    )
    csv_args_parser.add_argument(
        "-s",
        "--email-separator",
        default=",",
        help="""In case of multiple mail addresses inside the email-field specify their
        separator.""",
    )
    smtp_args_parser = main_parser.add_argument_group(
        "SMTP Arguments",
        """If you would like to test without actually sending any mails set this values
        to localhost:8025 and proceed without authentication and encryption. Then start
        a development server via `python3 -m smtpd -n -c DebuggingServer -u`.""",
    )
    smtp_args_parser.add_argument(
        "--smtp-server", type=str, default="localhost", help="The SMTP server to use"
    )
    smtp_args_parser.add_argument(
        "--smtp-port",
        type=int,
        default=587,
        help="The SMTP port the server is listening on",
    )
    smtp_args_parser.add_argument(
        "--smtp-user",
        type=str,
        default=getuser(),
        help="The username used to connect to the smtp server",
    )
    smtp_args_parser.add_argument(
        "--no-auth",
        action="store_true",
        help="Do not ask for a smtp password and skip authentication attempt",
    )
    smtp_args_parser.add_argument(
        "--no-tls",
        action="store_true",
        help="Do not try to switch to an encrypted connection.",
    )
    verbosity_args_group = main_parser.add_argument_group(
        "Verbosity Arguments",
        """Control the level of messages of the program. All messages beside actual
        output are written to STDERR.""",
    )
    verbosity_args = verbosity_args_group.add_mutually_exclusive_group()
    verbosity_args.add_argument(
        "-d", "--debug", action="store_true", help="Show debug messages"
    )
    verbosity_args.add_argument(
        "-q", "--quiet", action="store_true", help="Show no other messages except"
    )
    verbosity_args_group.add_argument(
        "-l",
        "--log-output",
        type=FileType("a"),
        default=stderr,
        help="Where to write log messages, appending if file already exists.",
    )

    args = main_parser.parse_args()

    def setup_logging(log_level):
        logging.basicConfig(
            level=log_level,
            format=_logging_format,
            stream=args.log_output,
            datefmt=_date_format,
        )

    if args.debug:
        setup_logging(logging.DEBUG)
    elif args.quiet:
        setup_logging(logging.ERROR)
    else:
        setup_logging(logging.INFO)
    logging.debug("Received command line args {}".format(args))

    already_sent_hashes = set()  # type: Set[str]

    # let's see whether any hash file is given and create it if necessary
    if args.hash_file:
        try:
            if args.hash_file.exists():
                with args.hash_file.open() as file:
                    for line in file.readlines():
                        if not line or line.strip().startswith("#"):
                            continue
                        else:
                            already_sent_hashes.add(line.strip())
                logging.info(
                    "Processed {} entries from {!r} to skip".format(
                        len(already_sent_hashes), args.hash_file.name
                    )
                )

            else:
                with args.hash_file.open("w") as file:
                    file.write(
                        "# Created {}. See `{} --help` for more information\n".format(
                            now(), argv[0]
                        )
                    )
                logging.debug(
                    "Created non existent hash-file {!r}".format(args.hash_file.name)
                )
        except PermissionError:
            logging.error(
                "Wrong permissions for hash-file {!r}. Aborting".format(
                    args.hash_file.name
                )
            )
            return 1
    else:
        logging.warning(
            "No hash file specified to store the mail addresses of the "
            "receivers of this run!"
        )

    try:
        csv_file = DictReader(args.csv_file)
    except csv_error as e:
        logging.error(
            "Could not read template from {}. The following error occurred {}".format(
                args.csv_file.name, e
            )
        )
        return 1

    logging.debug(
        "Parsed CSV file {!r} with headers {}".format(
            args.csv_file.name, csv_file.fieldnames
        )
    )

    template = Template(args.template_file.read())

    logging.debug("Constructed template from {!r}.".format(args.template_file.name))

    try:
        smtp_conn = SMTP(args.smtp_server, args.smtp_port)
    except ConnectionRefusedError:
        logging.error(
            "Could not connect to server '{}:{}'. "
            "Please check its address and port number.".format(
                args.smtp_server, args.smtp_port
            )
        )
        return 1

    if not args.no_tls:
        try:
            smtp_conn.starttls()
        except SMTPException as e:
            logging.error(
                "Could not switch to STARTTLS connection. Aborting. See `help` "
                "to ignore such errors."
            )
            return 1
    else:
        logging.info("Skipping switch to encrypted connection as requested.")
    logging.debug("Created connection to server {}".format(args.smtp_server))

    if not args.no_auth:
        try:
            smtp_pass = getpass(prompt="Please enter your smtp password: ")
        except EOFError:
            logging.error("Received EOF. Cannot continue without password. Exiting")
            return 2
        try:
            smtp_conn.login(args.smtp_user, smtp_pass)
        except (SMTPException, SMTPAuthenticationError) as e:
            logging.error(
                "Could not login with given given password for user {}. "
                "Maybe wrong password?".format(args.smtp_user)
            )
            return 1
        logging.debug(
            "Successfully logged in as {}@{}".format(args.smtp_user, args.smtp_server)
        )
    else:
        logging.info("Skipping authentication as requested.")

    first_hash_to_add = True
    for receiver in csv_file:
        logging.debug("Processing entry: {}".format(receiver))
        try:
            entry_identifier = "[{}]".format(receiver[args.email_field])
        except KeyError:
            logging.error(
                "Entry {} contains no address field {}. Aborting.".format(
                    receiver, args.email_field
                )
            )
            return 1
        # let's check whether any filter are given and skip entry if so
        skip_entry = False
        for field_to_check, regex in args.filter or []:
            try:
                if not match(regex, receiver[field_to_check]):
                    logging.info(
                        "{}, failed filter {!r}".format(entry_identifier, regex)
                    )
                    skip_entry = True
            except KeyError:
                logging.error(
                    "Cannot apply filter {!r} to nonexistent field {!r}, Aborting.".format(
                        regex, field_to_check
                    )
                )
                return 1
        if skip_entry:
            logging.warning("Skipping {} due to filters.".format(entry_identifier))
            continue
        logging.debug("Constructing mail for {}".format(entry_identifier))
        try:
            body = template.substitute(receiver)
        except KeyError as e:
            logging.error(
                "Template contains an unsubstituted Placeholder: {}. Aborting".format(e)
            )
            return 1
        except ValueError as e:
            logging.error("The template contains an error: {!r}. Aborting".format(e))
            return 1
        if args.attachment:
            logging.debug("Processing attachments")
            msg = MIMEMultipart()
            msg.attach(MIMEText(body))
            for attachment in args.attachment:
                attachment_name = attachment.name.split(sep)[-1]
                logging.debug("Processing attachment {}".format(attachment_name))
                part = MIMEApplication(attachment.read(), Name=attachment_name)
                part["Content-Disposition"] = 'attachment; filename="{}"'.format(
                    attachment_name
                )
                msg.attach(part)
                attachment.seek(0)

        else:
            msg = MIMEText(body)  # type: ignore
        msg["From"] = args.from_
        if args.reply_to:
            msg["Reply-To"] = args.reply_to
        msg["Subject"] = args.subject
        for mail_address in receiver[args.email_field].split(args.email_separator):
            mail_address = mail_address.strip()
            msg["To"] = mail_address
            if md5(mail_address) in already_sent_hashes:
                logging.info(
                    "Skipped {} since it is present in the hash-file".format(
                        mail_address
                    )
                )
                continue
            logging.debug("Sending mail to {!r}".format(mail_address))

            try:
                smtp_conn.sendmail(
                    args.smtp_user, mail_address.strip(), msg.as_string()
                )
            except SMTPException:
                logging.exception(
                    "The following error occurred during sending, stacktrace is "
                    "appended. Aborting"
                )
                return 1
            if args.hash_file and not args.no_update:
                with args.hash_file.open("a") as file:
                    if first_hash_to_add:
                        file.write("# Entries from {}\n".format(now()))
                        first_hash_to_add = False
                    file.write("{}\n".format(md5(mail_address)))
                logging.debug(
                    "Added md5-hash of {!r} to hash-file".format(mail_address)
                )

            logging.info("Sent mail to: {!r}".format(mail_address))
    smtp_conn.quit()

    return 0


if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        print("Received Ctrl+c. Good Bye")
# vim: textwidth=88
