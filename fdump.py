#!/usr/bin/env python3

import configparser
import sys
import getopt

__author__ = 'Joe Aranbayev <Joseph.Aranbayev@hdsupply.com>'


class ScanCounter:
    config = configparser.ConfigParser()
    critical_max = 0
    high_max = 0
    medium_max = 0
    low_max = 0

    # setup file source
    fortify_file = None
    critical = 0
    high = 0
    medium = 0
    low = 0

    def __init__(self, fortify_file, config_path):
        # setup configuration file
        self.config.read_file(open(config_path))
        self.critical_max = self.config \
            .getint('Severity Threshold', 'Criticals')
        self.high_max = self.config.getint('Severity Threshold', 'Highs')
        self.medium_max = self.config.getint('Severity Threshold', 'Mediums')
        self.low_max = self.config.getint('Severity Threshold', 'Lows')

        # setup result file source
        self.fortify_file = fortify_file

    def compute(self):
        # parse the fortify output file
        with open(self.fortify_file) as f:
            for line in f:
                if 'critical' in line:
                    self.critical += 1
                elif 'high' in line:
                    self.high += 1
                elif 'medium' in line:
                    self.medium += 1
                elif 'low' in line:
                    self.low += 1

        print('=== Fortify Report ===')
        print('# of criticals: {}'.format(self.critical))
        print('# of highs: {}'.format(self.high))
        print('# of mediums: {}'.format(self.medium))
        print('# of lows: {}\n'.format(self.low))

        # logic to determine pass/fail based on config
        scan_pass = True
        scan_result = 'PASS'
        if self.critical >= self.critical_max:
            scan_pass = False
        if self.high >= self.high_max:
            scan_pass = False
        if self.medium >= self.medium_max:
            scan_pass = False
        if self.low >= self.low_max:
            scan_pass = False

        if not scan_pass:
            scan_result = 'FAIL'
            print('Result: {}'.format(scan_result))
            return 1
        else:
            print('Result: {}'.format(scan_result))
        return 0


def main(argv):
    configfile = None
    inputfile = None
    
    try:
        opts, args = getopt \
            .getopt(argv, 'c:i:h', ['configfile=', 'inputfile='])
    except getopt.GetoptError:
        print('fdump.py -c <configfile> -i <inputfile>', file=sys.stderr)
        return 2
    for opt, arg in opts:
        if opt == '-h':
            print('fdump.py -c <configfile> -i <inputfile>')
            return 0
        elif opt in ('-i', '--inputfile'):
            inputfile = arg
        elif opt in ('-c', '--configfile'):
            configfile = arg
        else:
            return 2
            
    scalc = ScanCounter(inputfile, configfile)
    return scalc.compute()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
