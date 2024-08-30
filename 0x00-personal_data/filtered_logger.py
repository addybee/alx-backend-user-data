#!/usr/bin/env python3
"""Redacts sensitive information in a message based on
        the specified fields."""
import re
from typing import List
import logging


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """constructor for redactformatter"""
        self._logrecord = fields
        super(RedactingFormatter, self).__init__(self.FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        """format the output"""
        filter_datum(self._logrecord, self.REDACTION,
                     logging.getLogRecordFactory(), self.SEPARATOR)


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """ Redacts sensitive information in a message based on
        the specified fields.
    """
    for field in fields:
        pattern = r"(?<={}=)[\w!%'/:<=>@`\"]*{}".format(field, separator)
        message = re.sub(pattern, redaction + separator, message)
    return message
