###############################################################################
# DARPA AIMEE - CFGAVE: Utility functions
# Author: Michael D. Brown
# Copyright Georgia Tech Research Institute, 2020
###############################################################################

import os
from datetime import datetime

def create_output_directory(prefix, timestamp=True):
    """
    Create a subdirectory in the current directory for output like logs, fuzzing results, etc.
    :param str prefix: String to prefix to the timestamp on the directory label
    :param bool timestamp: Whether or not to timstamp the directory.
    :return: Name of the directory created by the system
    :rtype: str
    :raises: OSError if an error occurs during directory creation.
    """
    if timestamp:
        directory_name = prefix + str(datetime.now())
    else:
        directory_name = prefix
    os.makedirs(directory_name)
    return directory_name