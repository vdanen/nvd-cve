#!/usr/bin/env python3

import argparse
import datetime
import gzip
import os
import json
import urllib.request

start_year   = 1999
#current_year = 2004
current_year = int(datetime.datetime.today().strftime('%Y'))


class CVE:
    def __init__(self, cve_entry):
        self.cve_dict = {}
        for key, value in cve_entry.items():
            self.cve_dict[key] = value

        self.cve = cve_entry['cve']['CVE_data_meta']['ID']
        self.publishedDate = self.cve_dict['publishedDate']
        self.publishedDateTime = datetime.datetime.strptime(self.cve_dict['publishedDate'], '%Y-%m-%dT%H:%MZ')
        self.lastModifiedDate = self.cve_dict['lastModifiedDate']
        self.lastModifiedDateTime = datetime.datetime.strptime(self.cve_dict['lastModifiedDate'], '%Y-%m-%dT%H:%MZ')

        descriptions = []
        for d in cve_entry['cve']['description']['description_data']:
            descriptions.append(d['value'])
        self.cve_dict['descriptions'] = descriptions

        self.description = 'No description info'
        if len(descriptions) > 0:
            self.description = '|'.join(descriptions)

    def __str__(self):
        return '{}: {}, {}'.format(self.cve,
                                   self.publishedDate,
                                   self.description[:30])


def download(url, localfile):
    # download an individual file
    if '/' not in url:
        print('No URL provided!')
        return None

    print(f'Downloading {url}...')
    try:
        urllib.request.urlretrieve(url, localfile)
        return localfile
    except Exception as e:
        print(f'Failed to download {url}')
        print(e)

    return None


def download_gzips():
    # download the NVD gzip files
    hosturl = 'https://nvd.nist.gov/feeds/json/cve/1.1/'
    fname = 'nvdcve-1.1-'

    i = 2002   # NVD files start in 2002
    years = [f'{fname}{i}.json.gz']
    while i < current_year:
        i = i + 1
        years.append(f'{fname}{i}.json.gz')

#    print(years)

    downloaded = []

    for gzfile in years:
        if os.path.isfile(gzfile):
            # don't download if we've already downloaded today
            dt_now = datetime.datetime.now()
            dt_cre = datetime.datetime.fromtimestamp(os.path.getctime(gzfile))
            if (dt_now - dt_cre).total_seconds() > 60*60*24:
                print(f'{gzfile} is older than 24h, refreshing...')
                dl_file = download(f'{hosturl}{gzfile}', gzfile)
                if dl_file is not None:
                    downloaded.append(gzfile)
        else:
            dl_file = download(f'{hosturl}{gzfile}', gzfile)
            if dl_file is not None:
                downloaded.append(gzfile)

    return years


def parse_nvd(gzfile):
    # gunzip and return JSON
    if not os.path.isfile(gzfile):
        print(f'File {gzfile} does not exist!')
        return None

    with gzip.open(gzfile, 'rb') as f:
#        print(f'Importing records from {gzfile}')
        j = json.loads(f.read())
#        records = len(j['CVE_Items'])
#        print(f'Number of CVE entries loaded: {records}')

        cve_entries = [CVE(cve_dict) for cve_dict in j['CVE_Items']]

    return cve_entries


def main():
    parser = argparse.ArgumentParser(description='NVD parsing tool')
    parser.add_argument('--year-stats', dest='year_stats', action='store_true', default=False,
                        help='Display CVE count by year')

    args = parser.parse_args()

    print('Loading and downloading NVD entries ')
    gzips = download_gzips()
    cves  = []

    for x in gzips:
        # load local and downloaded files
        cves.extend(parse_nvd(x))

#    print(f'Found {len(cves)} entries in CVE list')

    if args.year_stats:
        print('CVE counts per year')
        years = list(range(start_year, current_year+1, 1))
        for y in years:
            x = 0
            for c in cves:
                if str(y) in c.publishedDate:
                    x += 1
            print(f'  {y}: {x}')


if __name__ == '__main__':
    main()
