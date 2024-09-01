#!/usr/bin/env python3
"""Redacts sensitive information in a message based on
        the specified fields."""
import re
from typing import List
import logging
import os
from mysql.connector import Error
import mysql.connector

PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


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
        return filter_datum(self._logrecord, self.REDACTION,
                            super().format(record), self.SEPARATOR)


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """ Redacts sensitive information in a message based on
        the specified fields.
    """
    for field in fields:
        pattern = r"(?<={}=).*?{}".format(field, separator)
        message = re.sub(pattern, redaction + separator, message)
    return message


def get_logger() -> logging.Logger:
    """Creates and returns a logger with a specific configuration.

    The logger is configured to log messages at the INFO level and
    outputs them to the console with redacted sensitive information.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger('user_data')
    logger.setLevel(logging.INFO)

    # Create a stream handler
    file_handler = logging.StreamHandler()

    # Set the formatter for the handler
    file_handler.setFormatter(RedactingFormatter(list(PII_FIELDS)))

    # Add the handler to the logger
    logger.addHandler(file_handler)
    logger.propagate = False

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """ Establishes a connection to the MySQL database and
        returns the connection object.

    Returns:
        mysql.connector.connection.MySQLConnection: A MySQLConnection object.
    """
    try:
        connection = mysql.connector.connect(
            host=os.environ.get('PERSONAL_DATA_DB_HOST', 'localhost'),
            user=os.environ.get('PERSONAL_DATA_DB_USERNAME', 'root'),
            password=os.environ.get('PERSONAL_DATA_DB_PASSWORD', ''),
            database=os.environ.get('PERSONAL_DATA_DB_NAME')
        )
        if connection.is_connected():
            # print("Successfully connected to the database")
            return connection
        else:
            # print("Failed to connect to the database")
            return None
    except Error as e:
        # print(f"Error: {e}")
        return None
