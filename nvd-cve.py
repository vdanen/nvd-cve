#!/usr/bin/env python3

import argparse
import datetime
import gzip
import json
import sqlite3
import os
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

        self.type = 'VALID'
        if '** REJECT **' in self.description:
            self.type = 'REJECT'
        if '** DISPUTED **' in self.description:
            self.type = 'DISPUTED'
        if '** RESERVED **' in self.description:
            self.type = 'RESERVED'

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
        j = json.loads(f.read())

        cve_entries = [CVE(cve_dict) for cve_dict in j['CVE_Items']]

    return cve_entries


def main():
    parser = argparse.ArgumentParser(description='NVD parsing tool')
    parser.add_argument('--import', dest='importcve', action='store_true', default=False,
                        help='Import data from NVD')
    parser.add_argument('--year-stats', dest='year_stats', action='store_true', default=False,
                        help='Display CVE count by year')

    args = parser.parse_args()

    conn = sqlite3.connect('nvdcves.db')
    c    = conn.cursor()

    if args.importcve:
        print('Loading and downloading NVD entries ')
        gzips = download_gzips()
        cves  = []

        for x in gzips:
            # load local and downloaded files
            cves.extend(parse_nvd(x))

        data       = []
        line_count = 0
        for row in cves:
            if line_count == 0:
                try:
                    c.execute('DROP TABLE cves')
                except:
                    print('Initializing database')
                c.execute('CREATE TABLE cves (Num int, Id text, lastModifiedDate text, publishedDate text, type text, description text, cve_dict text)')
                line_count += 1
            else:
                # tuple to add to database
                data.append((line_count,
                             row.cve,
                             row.lastModifiedDate,
                             row.publishedDate,
                             row.type,
                             json.dumps(row.description),
                             json.dumps(row.cve_dict)))
                line_count += 1

        c.executemany('INSERT INTO cves VALUES (?,?,?,?,?,?,?)', data)
        print(f'Imported {line_count-1} rows')
        conn.commit()
        conn.close()
        exit(0)

    if args.year_stats:
        print('CVE counts per year')
        years = list(range(start_year, current_year+1, 1))
        last_year = 0
        for y in years:
            cve_all      = 0
            cve_rejected = 0
            cve_disputed = 0
            cve_reserved = 0
            for row in c.execute('SELECT COUNT(Num) FROM cves WHERE publishedDate LIKE ?', [f'%{y}%']):
                cve_all = row[0]
            for row in c.execute('SELECT COUNT(Num) FROM cves WHERE publishedDate LIKE ? AND type = ?', [f'%{y}%', 'REJECT']):
                cve_rejected = row[0]
            for row in c.execute('SELECT COUNT(Num) FROM cves WHERE publishedDate LIKE ? AND type = ?', [f'%{y}%', 'DISPUTED']):
                cve_disputed = row[0]
            for row in c.execute('SELECT COUNT(Num) FROM cves WHERE publishedDate LIKE ? AND type = ?', [f'%{y}%', 'RESERVED']):
                cve_reserved = row[0]
            cve_valid = cve_all - cve_rejected - cve_disputed - cve_reserved

            if last_year > 0:
                # calculate YoY growth
                cve_yoy = ((cve_valid - last_year) / last_year) * 100
            else:
                cve_yoy = 0
            last_year = cve_valid

            print(f'{y}: {cve_valid} YoY: {cve_yoy:.2f}% (all={cve_all},reject={cve_rejected},disputed={cve_disputed},reserved={cve_reserved}')


if __name__ == '__main__':
    main()
