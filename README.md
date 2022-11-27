# nvd-cve
NVD CVE parser

Inspired by
https://github.com/andreas-31/nvd-cve-parse/blob/master/nvdcve.py this
script downloads and parses the NVD CVE JSON feeds and imports it into an
SQLite database to query and get statistics on.


Usage:

* ```--import``` downloads and imports data from NVD and imports into the
  local SQLite database; will only download NVD JSON feeds if they've not
  been downloaded in the last 24h
* ```---year-stats``` displays the CVE counts per year in the NVD database
* ```--year``` used with other arguments will constrain to displaying data
  for the specified year (i.e. ```--year 2022``` to display only results
  for 2022)
* ```--severity-stats Vx``` where *Vx* is one of *V2* (to display
  CVSSv2-based severities), *V3* (to display CVSSv3-based severities) or
  *ALL* to display the highest severity of either CVSSv2 or CVSSv3;
  displays the number of corresponding Low, Medium. High or Critical CVEs,
  by year
* ```--cve``` to display details of a specific CVE, can be used multiple
  times to display data on multiple CVEs

