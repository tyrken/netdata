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
        'lines': [['num_routes', None, 'absolute']]
    }}
CIDR_MATCHER = re.compile(
    '^(([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?)$')

# TODO: Host path to proc file under docker?
LINUX_IPV4_ROUTES_PROCFILE = '/proc/net/route'


class Service(ExecutableService):

    def __init__(self, configuration=None, name=None):
        ExecutableService.__init__(
            self, configuration=configuration, name=name)
        self.order = ORDER
        self.definitions = deepcopy(CHARTS)
        self.tested_cidrs = {}
        for cidr_name, cidr_string_or_list in self.configuration.get('tested_cidrs', {}).items():
            self.tested_cidrs[cidr_name] = [cidr_string_or_list] if isinstance(
                cidr_string_or_list, basestring) else cidr_string_or_list

    def check(self):
        cidrs_ok = True
        for cidr_name, cidrs in self.tested_cidrs.items():
            for cidr in cidrs:
                if not CIDR_MATCHER.match(cidr):
                    self.error('Syntax error with CIDR: ' + cidr)
                    cidrs_ok = False
            self.definitions['ipv4']['lines'].append(
                [cidr_name, None, 'absolute'])
        if access(LINUX_IPV4_ROUTES_PROCFILE, R_OK):
            self.info('Reading routes via: ' + LINUX_IPV4_ROUTES_PROCFILE)
            self.proc_file_dest_index = -1
            self.get_route_cidrs = self._route_cidrs_from_proc_file
            return cidrs_ok
        self.command = 'ip -4 route list' if self.find_binary('ip') else 'netstat -rn4'
        self.info('Reading routes via command: ' + self.command)
        self.get_route_cidrs = self._route_cidrs_from_command
        return cidrs_ok and ExecutableService.check(self)

    def _route_cidrs_from_proc_file(self):
        """
        Extract route table cidrs from /proc/net/route
        :return: set
        """
        route_cidrs = set()
        with open(LINUX_IPV4_ROUTES_PROCFILE) as route_procfile:
            rows = route_procfile.readlines()
            try:
                if self.proc_file_dest_index < 0:
                    title = rows[0].split('\t')
                    self.proc_file_dest_index = title.index('Destination')
                    self.proc_file_mask_index = title.index('Mask')
                for data_row in rows[1:]:
                    elems = data_row.split('\t')
                    reversed_dest = int(elems[self.proc_file_dest_index], 16)
                    prefix_len = bin(int(elems[self.proc_file_mask_index], 16)).count('1')
                    route_cidrs.add('{}.{}.{}.{}/{}'.format(reversed_dest & 0xff, (reversed_dest >> 8) &
                                                            0xff, (reversed_dest >> 16) & 0xff, reversed_dest >> 24, prefix_len))
            except ValueError:
                self.error('Failed to parse ' + LINUX_IPV4_ROUTES_PROCFILE)
        return route_cidrs

    def _route_cidrs_from_command(self):
        """
        Extract route table cidrs from ip or netstat command
        :return: set
        """
        route_cidrs = set()
        raw = self._get_raw_data()
        genmask_found = False
        for line in raw:
            fields = line.split()
            first_field = fields[0]
            if genmask_found:
                genmask = fields[2]
                prefix_length = str(''.join(bin(int(i)) for i in genmask.split('.')).count('1'))
                route_cidrs.add(first_field + '/' + prefix_length)
            else:
                if first_field == 'Destination' and fields[2] == 'Genmask':
                    genmask_found = True
                elif first_field == 'default':
                    route_cidrs.add('0.0.0.0/0')
                elif CIDR_MATCHER.match(first_field):
                    if '/' not in first_field:
                        first_field += '/32'
                    route_cidrs.add(first_field)
        return route_cidrs

    def _get_data(self):
        """
        Parse routing table to extract metrics
        :return: dict
        """
        route_cidrs = self.get_route_cidrs()
        if len(route_cidrs) == 0:
            self.error('No routes detected - likely edge case for routes.chart.py')
            return None
        data = {'num_routes': len(route_cidrs)}
        for cidr_name, cidrs in self.tested_cidrs.items():
            data[cidr_name] = 1 if any(c in route_cidrs for c in cidrs) else 0
        return data
