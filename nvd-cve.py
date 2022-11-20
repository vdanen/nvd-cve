#!/usr/bin/env python3

import argparse
import datetime
import gzip
import json
import sqlite3
import os
import urllib.request
from tqdm import tqdm

start_year   = 1999
#current_year = 2004
current_year = int(datetime.datetime.today().strftime('%Y'))

class DownloadProgressBar(tqdm):
    def update_to(self, b=1, bsize=1, tsize=None):
        if tsize is not None:
            self.total = tsize
        self.update(b * bsize - self.n)


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

        self.cvss2_score    = 0
        self.cvss2_severity = ''
        self.cvss3_score    = 0
        self.cvss3_severity = ''
        self.scoring        = 0
        self.impact         = 'NONE'

        impact_weight  = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        impact_highest = 0
        for key in ['baseMetricV2', 'baseMetricV3']:
            try:
                if key == 'baseMetricV2':
                    self.cvss2_score = float(self.cve_dict['impact'][key]['cvssV2']['baseScore'])
                    self.cvss2_severity = self.cve_dict['impact'][key]['severity']
                    if impact_weight[self.cvss2_severity] > impact_highest:
                        impact_highest = impact_weight[self.cvss2_severity]
                elif key == 'baseMetricV3':
                    self.cvss3_score = float(self.cve_dict['impact'][key]['cvssV3']['baseScore'])
                    self.cvss3_severity = self.cve_dict['impact'][key]['cvssV3']['baseSeverity']
                    if impact_weight[self.cvss3_severity] > impact_highest:
                        impact_highest = impact_weight[self.cvss3_severity]
            except:
                pass

        for k, v in impact_weight.items():
            if impact_weight[k] == impact_highest:
                self.impact = k

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
        with DownloadProgressBar(unit='B', unit_scale=True, miniters=1, desc=url.split('/')[-1]) as t:
            urllib.request.urlretrieve(url, filename=localfile, reporthook=t.update_to)
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
    parser.add_argument('--severity-stats', dest='severity_stats', metavar='Vx', default=None,
                        help='Display CVE severity counts by year using either CVSS V2, V3, V4 or ALL to print the highest of any')
    parser.add_argument('--year', dest='const_year', metavar='YEAR', default=None, help='Constrain results to YEAR')
    parser.add_argument('--cve', dest='cve', action='append', help='Display CVE; can use multiple times')

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
                c.execute('CREATE TABLE cves (Num int, Id text, lastModifiedDate text, publishedDate text, type text, severity3 text, severity2 text, impact text, description text, cve_dict text)')
                line_count += 1
            else:
                # tuple to add to database
                data.append((line_count,
                             row.cve,
                             row.lastModifiedDate,
                             row.publishedDate,
                             row.type,
                             row.cvss3_severity,
                             row.cvss2_severity,
                             row.impact,
                             json.dumps(row.description),
                             json.dumps(row.cve_dict)))
                line_count += 1

        c.executemany('INSERT INTO cves VALUES (?,?,?,?,?,?,?,?,?,?)', data)
        print(f'Imported {line_count-1} rows')
        conn.commit()
        conn.close()
        exit(0)

    if args.year_stats:
        print('Total CVE counts per year')
        if args.const_year:
            years = [args.const_year]
        else:
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

            print(f'{y}: {cve_valid} YoY: {cve_yoy:.2f}% (all={cve_all},reject={cve_rejected},disputed={cve_disputed},reserved={cve_reserved})')

    if args.severity_stats:
        if args.severity_stats not in ['V2', 'V3', 'ALL']:
            # TODO: when CVSSv4 is starting to be used, this needs to be updated..
            print('Invalid argument, expecting "V2", "V3", "V4" or "ALL"')
            exit(1)
        print(f'CVE counts per year by CVSS {args.severity_stats} severity')

        if args.const_year:
            years = [args.const_year]
        else:
            years = list(range(start_year, current_year+1, 1))

        for y in years:
            cve_critical = 0
            cve_high     = 0
            cve_medium   = 0
            cve_low      = 0
            cve_total    = 0
            if args.severity_stats == 'V2':
                for row in c.execute('SELECT COUNT(Num) FROM cves WHERE publishedDate LIKE ? AND severity2 = ?', [f'%{y}%', 'CRITICAL']):
                    cve_critical = row[0]
                for row in c.execute('SELECT COUNT(Num) FROM cves WHERE publishedDate LIKE ? AND severity2 = ?',[f'%{y}%', 'HIGH']):
                    cve_high = row[0]
                for row in c.execute('SELECT COUNT(Num) FROM cves WHERE publishedDate LIKE ? AND severity2 = ?', [f'%{y}%', 'MEDIUM']):
                    cve_medium = row[0]
                for row in c.execute('SELECT COUNT(Num) FROM cves WHERE publishedDate LIKE ? AND severity2 = ?', [f'%{y}%', 'LOW']):
                    cve_low = row[0]
            elif args.severity_stats == 'V3':
                for row in c.execute('SELECT COUNT(Num) FROM cves WHERE publishedDate LIKE ? AND severity3 = ?', [f'%{y}%', 'CRITICAL']):
                    cve_critical = row[0]
                for row in c.execute('SELECT COUNT(Num) FROM cves WHERE publishedDate LIKE ? AND severity3 = ?',[f'%{y}%', 'HIGH']):
                    cve_high = row[0]
                for row in c.execute('SELECT COUNT(Num) FROM cves WHERE publishedDate LIKE ? AND severity3 = ?', [f'%{y}%', 'MEDIUM']):
                    cve_medium = row[0]
                for row in c.execute('SELECT COUNT(Num) FROM cves WHERE publishedDate LIKE ? AND severity3 = ?', [f'%{y}%', 'LOW']):
                    cve_low = row[0]
            elif args.severity_stats == 'ALL':
                for row in c.execute('SELECT COUNT(Num) FROM cves WHERE publishedDate LIKE ? AND impact = ?', [f'%{y}%', 'CRITICAL']):
                    cve_critical = row[0]
                for row in c.execute('SELECT COUNT(Num) FROM cves WHERE publishedDate LIKE ? AND impact = ?',[f'%{y}%', 'HIGH']):
                    cve_high = row[0]
                for row in c.execute('SELECT COUNT(Num) FROM cves WHERE publishedDate LIKE ? AND impact = ?', [f'%{y}%', 'MEDIUM']):
                    cve_medium = row[0]
                for row in c.execute('SELECT COUNT(Num) FROM cves WHERE publishedDate LIKE ? AND impact = ?', [f'%{y}%', 'LOW']):
                    cve_low = row[0]
            else:
                return

            cve_total = cve_critical + cve_high + cve_medium + cve_low
            print(f'{y}: CRITICAL={cve_critical},HIGH={cve_high},MEDIUM={cve_medium},LOW={cve_low}  TOTAL={cve_total}')

    if args.cve:
        for x in args.cve:
            for row in c.execute('SELECT cve_dict FROM cves WHERE Id = ?', [x]):
                print(row)
                cve = CVE(json.loads(row[0]))
                print(cve.cve)
                print(cve.cvss3_score)
                print(cve.cvss3_severity)

if __name__ == '__main__':
    main()
