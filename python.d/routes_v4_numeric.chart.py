# -*- coding: utf-8 -*-
# Description: routes netdata python.d module
# Author: Tristan Keen

from copy import deepcopy
from os import access, R_OK
import re

from base import ExecutableService

# default module values (can be overridden per job in `config`)
update_every = 5
priority = 60000
retries = 60

# charts order (can be overridden if you want less charts, or different order)
ORDER = ['ipv4']
CHARTS = {
    'ipv4': {
        'options': [None, 'IPv4 Routes', 'routes found', 'ipv4', 'ipv4.routes', 'line'],
        'lines': []
    }}
CIDR_MATCHER = re.compile(
    '^(default|([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(?:\/([0-9]|[1-2][0-9]|3[0-2]))?)(?:(?:\s.*)?)$')

# TODO: Host path to proc file under docker?
LINUX_IPV4_ROUTES_PROCFILE = '/proc/net/route'


class Service(ExecutableService):

    def __init__(self, configuration=None, name=None):
        ExecutableService.__init__(
            self, configuration=configuration, name=name)
        self.order = ORDER
        self.definitions = deepcopy(CHARTS)
        self.tests = self.configuration.get('tests')

    def check(self):
        if not (self.tests and hasattr(self.tests, 'keys')):
            self.error('tests not defined')
            return False

        # TODO: Allow cidr to be an array
        self.numeric_cidrs_to_test = []
        for test_name, cidr in self.tests.items():
            self.definitions['ipv4']['lines'].append(
                [test_name, None, 'absolute'])
            numeric_cidr = self._cidr_to_number(cidr)
            if numeric_cidr < 0:
                self.error('Unparsable CIDR: ' + cidr)
                return False
            self.numeric_cidrs_to_test.append((test_name, numeric_cidr))

        if access(LINUX_IPV4_ROUTES_PROCFILE + 'x', R_OK):
            with open(LINUX_IPV4_ROUTES_PROCFILE) as route_procfile:
                raw_data = route_procfile.readlines()
            try:
                titles = raw_data[0].split('\t')
                self.procfile_dst_index = titles.index('Destination')
                self.procfile_mask_index = titles.index('Mask')
                self.get_routes_as_numeric_cidrs = self._read_proc_file
                return True
            except ValueError:
                self.info('Could not read/parse ' + LINUX_IPV4_ROUTES_PROCFILE)

        self.get_routes_as_numeric_cidrs = self._run_command
        self.command = 'ip -4 route list' if self.find_binary('ip') else 'netxstat -rn4'
        if not ExecutableService.check(self):
            self.error('Failed to find route info command: ' + self.command)
            return False

        raw_output = self._get_raw_data()
        if not raw_output:
            self.error('Failed to run route info command: ' + string.join(command))
            return False
        self._parse_command_output = self._cidr_to_number
        for line in raw_output:
            if "Genmask" in line:
                self._parse_command_output = self._parse_netstat_with_mask_line
                break

        return True

    def _read_proc_file(self):
        """
        Extract route table cidrs from /proc/net/route
        :return: set
        """
        routes_as_numeric_cidrs = set()
        with open(LINUX_IPV4_ROUTES_PROCFILE) as route_procfile:
            raw_data = route_procfile.readlines()
            for data_row in raw_data[1:]:
                elems = data_row.split('\t')
                reversed_dest = int(elems[self.procfile_dst_index], 16)
                prefix_len = bin(int(elems[self.procfile_mask_index], 16)).count('1')
                routes_as_numeric_cidrs.add((reversed_dest << 8) + prefix_len)
        return routes_as_numeric_cidrs

    def _run_command(self):
        """
        Run ip or other command that returns cidrs and parse to numeric_cidrs
        :return: set
        """
        routes_as_numeric_cidrs = set()
        raw_output = self._get_raw_data()
        if raw_output:
            for line in raw_output:
                numeric_cidr = self._parse_command_output(line)
                if numeric_cidr >= 0:
                    routes_as_numeric_cidrs.add(numeric_cidr)
        return routes_as_numeric_cidrs

    def _parse_cidr_output(self):
        """
        Run ip or other command that returns cidrs and parse to numeric_cidrs
        :return: set
        """
        routes_as_numeric_cidrs = set()
        raw_output = self._get_raw_data()
        if raw_output:
            for line in raw_output:
                numeric_cidr = self._cidr_to_number(line)
                if numeric_cidr >= 0:
                    routes_as_numeric_cidrs.add(numeric_cidr)
        return routes_as_numeric_cidrs

    @staticmethod
    def _cidr_to_number(text):
        """
        Convert the CIDR of form A.B.C.D/E to a number formed as DCBAE in base 256,
        i.e. like the 32-bit reversed hex Destination from /proc/net/route
        bumped up by 8 bits with the prefix length added.
        """
        m = CIDR_MATCHER.match(text)
        if not m:
            return -1
        if m.group(1) == 'default':
            return 0
        # for i in range(0, 7):
        #     print m.group(i)
        prefix_length = 32 if m.group(6) == None else int(m.group(6))
        return ((((int(m.group(5)) << 8) + int(m.group(4)) << 8) + int(m.group(3)) << 8) + int(m.group(2)) << 8) + prefix_length

    @staticmethod
    def _dotted_quad_to_number(text):
        """
        Convert a dotted quad of form A.B.C.D to a number formed as DCBA in base 256,
        i.e. like the 32-bit reversed hex Destination from /proc/net/route
        """
        elems = text.split('.')
        if len(elems) != 4:
            return -1
        return (((int(elems[3]) << 8) + int(elems[2]) << 8) + int(elems[1]) << 8) + int(elems[0])

    @staticmethod
    def _parse_netstat_with_mask_line(text):
        fields = text.split()
        dest_rev = self._dotted_quad_to_number(fields[0])
        mask = self._dotted_quad_to_number(fields[2])
        # TODO
        return -1

    def _get_data(self):
        """
        Read routing table via selected strategy and extract metrics
        :return: dict
        """
        routes = self.get_routes_as_numeric_cidrs()
        if len(routes) == 0:
            self.error('No routes detected - likely bug in routes_v4.chart.py')
            return None
        data = {'num_routes': len(routes)}
        for test_name, numeric_cidr in self.numeric_cidrs_to_test:
            data[test_name] = 1 if numeric_cidr in routes else 0
        return data
