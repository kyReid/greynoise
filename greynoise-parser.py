from greynoise import GreyNoise
from ipaddress import ip_address
from os.path import exists
import argparse
import csv


def cmd_handler():
    """
    handles user input
    :return:
    """
    example = """
        example:
            python3 gn_analyzer -F [filename] -m (run malicious scans on IPs)
            python3 gn_analyzer -q [query command] (run greynoise queries)
        """

    parser = argparse.ArgumentParser(
        description='A purpose built tool for querying parsing requests using the greynoise API.', epilog=example,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-F', '--File', dest='ipfile', type=str, help='file containing IPs to analyze')
    parser.add_argument('-m', action='store_true', help='flag to check if any Ips from file are malicious.')
    parser.add_argument('-q', dest='query', type=str, help='Command to queries greynoise api')

    return parser.parse_args()


def check_private_ip(ip):
    """
    checks whether a given IP is private or public
    :param ip: IP address
    :return:
    """
    return True if ip_address(ip).is_private else False


def csv_writer(filename, data):
    """
    writes data to csv file
    :param filename: name of csv file
    :param data: data to write to file
    :return:
    """
    with open(filename, 'a', encoding='UTF8') as fopen:
        writer = csv.writer(fopen)
        writer.writerow(data)


def csv_clear(filename):
    """
    clears csv file
    :param filename: name of csv file
    :return:
    """
    with open(filename, 'w+') as f:
        f.close()


def malicious_check(api, ips):
    """
    runs greynoise api against file containing IP addresses in search of malicious IPs.
    :param api: greynoise api object
    :param ips: list of IP addresses
    :return:
    """
    filename = 'malicious.csv'
    header = ['IP Address', 'Classification', 'Tags', 'Country', 'Organization', 'OS', 'Scan']

    if exists(filename):
        csv_clear(filename)
    csv_writer(filename, header)

    for ip in ips:
        result = api.ip(ip)
        if check_private_ip(ip) is False:
            if result['seen'] is True and result['classification'] == 'malicious':
                parsed_results = [result["ip"], result["classification"], result["tags"], result["metadata"]["country"],
                                  result["metadata"]["organization"], result["metadata"]["os"],
                                  result["raw_data"]["scan"]]

                csv_writer(filename, parsed_results)


def parse_data(filename, result):
    """
    parses information from results and writes to csv file.
    :param filename: name of file to write to
    :param result: results of query command
    :return:
    """
    for index in range(len(result['data'])):
        parsed_results = [result['data'][index]['ip'], result['data'][index]['actor'],
                          result['data'][index]['classification'], result['data'][index]['tags'],
                          result['data'][index]['metadata']['country'],
                          result['data'][index]['metadata']['organization'], result['data'][index]['metadata']['tor'],
                          result['data'][index]['metadata']['os'], result['data'][index]['metadata']['category'],
                          result['data'][index]['raw_data']['scan'], result['data'][index]['bot'],
                          result['data'][index]['cve']]

        csv_writer(filename, parsed_results)


def targeted_ports(api, command):
    """
    queries greynoise and adds parsed results to a csv file.
    :param api: greynoise api object
    :param command: command from user input
    :return:
    """
    filename = 'targeted.csv'
    header = ['IP Address', 'Actor', 'Classification', 'Tags', 'Country', 'Organization', 'Tor', 'Operating System',
              'Category', 'Scans', 'Bot', 'CVE']

    if exists(filename):
        csv_clear(filename)
    csv_writer(filename, header)

    result = api.query(command)
    parse_data(filename, result)

    try:
        while result['scroll']:
            result = api.query(command, scroll=result["scroll"])
            parse_data(filename, result)
    except Exception:
        pass


def main():
    gn_api = GreyNoise()
    args = cmd_handler()

    if args.ipfile:
        with open(args.ipfile, 'r') as fopen:
            ips = [line.strip() for line in fopen]

    if args.ipfile is not None:
        if args.m:
            malicious_check(gn_api, ips)
    else:
        if args.query is not None:
            targeted_ports(gn_api, args.query)


if __name__ == '__main__':
    main()
