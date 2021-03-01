from requests import get, post
from datetime import datetime
from math import ceil
from bs4 import BeautifulSoup


class UserData:
    def __init__(self, username, password):
        self.username = username
        self.password = password


class Session:
    def __init__(self, userData, nexpose_url, verify=True):
        self.userData = userData
        self.nexpose_url = nexpose_url
        self.verify = verify
        self.headers = {
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest'
        }

    def login(self):
        data = f'nexposeccusername={self.userData.username}&nexposeccpassword={self.userData.password}'
        resp = post(f'{self.nexpose_url}/data/user/login', data=data,
                    headers=self.headers, verify=self.verify)
        self.headers['nexposeCCSessionID'] = resp.json()['sessionID']
        self.headers['Cookie'] = f'i18next=en; time-zone-offset=-180; nexposeCCSessionID={resp.json()["sessionID"]}'
        return self.headers

    def logout(self):
        resp = post(f'{self.nexpose_url}/logout.html', headers=self.headers, verify=self.verify)
        return resp


class Scanner:
    def __init__(self, Ses):
        self.nexpose_url = Ses.nexpose_url
        self.headers = Ses.login()
        self.verify = Ses.verify

    def scanHistory(self, requestBody=None):
        """:returned scan history(list[dict]). Return 25 last scans. Example:
        [{"endTime" : 1613543012197,
        "siteID" : 20,
        "scanName" : "wsuspc",
        "scanEngineID" : 5,
        "scanID" : 2586632,
        "newScan" : false,
        "siteName" : "siteName",
        "riskScore" : 1310.8462,
        "reason" : null,
        "startedByCD" : "A",
        "startedBy" : null,
        "liveHosts" : 1,
        "vulnerabilityCount" : 2,
        "vulnCriticalCount" : 0,
        "vulnModerateCount" : 1,
        "vulnSevereCount" : 1,
        "activeDuration" : 273152,
        "totalEngines" : 1,
        "scanEngineNameOrCount" : "scanEngineNameOrCount",
        "scanEngineName" : "scanEngineName",
        "duration" : 295791,
        "startTime" : 1613542716405,
        "status" : "C",
        "username" : "username",
        "paused" : false,
        "id" : 2586632}]

        """
        resp = post(f'{self.nexpose_url}/data/scan/global/scan-history',
                    data=requestBody,
                    headers=self.headers, verify=self.verify)
        return resp.json()['records']

    def lastScanSiteId(self):
        """
        return site id(tuple) by scan history if scan is scheduled and scan completed is today.
        Example return: [328, 328, 201]
         """
        site_ids = []
        for scan in self.scanHistory(
                requestBody='sort=-1&dir=-1&startIndex=-1&results=-1&table-id=global-completed-scans'):
            if scan['startedByCD'] == 'S':
                if datetime.fromtimestamp((scan['endTime'] // 1000)).strftime('%Y%m%d') == datetime.now().strftime(
                        '%Y%m%d'):
                    site_ids.append(scan['siteID'])
        return tuple(site_ids)

    def lastScanBySiteId(self, siteId):
        """
        :param siteId | identificator site, for example lastScanBySiteId(261)
        :return: scans
        return last scans id by site id if scan is scheduled
        Example return (2586647, 2586646, 2586598, 2586592, 2586589, 2586587, 2586580, 2586492, 2586418, 2586394)
        """
        scans = []
        for scan in post(f'{self.nexpose_url}/data/scan/site/{siteId}',
                         data='sort=-1&dir=-1&startIndex=-1&results=-1&table-id=site-completed-scans',
                         headers=self.headers, verify=self.verify).json()['records']:
            if scan['startedByCD'] == 'S':
                scans.append(scan['scanID'])
        return tuple(scans)

    def assetsByScan(self, scanId):
        """
        return devices id by scan id
        :param scanId: | identificator site, for example assetsByScan(261)
        :return: tuple(devices id)
        """
        assets = []
        resp = get(f'{self.nexpose_url}/data/asset/scan/{scanId}/complete-assets?sort='
                   '-1&dir=-1&startIndex=-1&results=500&table-id=scan-complete-assets',
                   headers=self.headers, verify=self.verify).json()
        pages = ceil(int(resp['totalRecords']) / 500)
        for i in range(pages):
            resp = get(f'{self.nexpose_url}/data/asset/scan/{scanId}/complete-assets?sort='
                       f'-1&dir=-1&startIndex={500 * i}&results=500&table-id=scan-complete-assets',
                       headers=self.headers, verify=self.verify).json()
            for asset in resp['records']:
                assets.append(asset['assetID'])
        return tuple(assets)

    def nodesByScan(self, scanId):
        """
        return nodes id by scan id
        :param scanId | identificator site, for example nodesByScan(2586534)
        :return dict(nodes) | return {ipaddress:node_id}
        Example return {'10.10.10.10': 218037225, '10.10.10.11': 218036746, '10.100.10.12': 218037223}
        """
        nodes = {}
        resp = get(f'{self.nexpose_url}/data/asset/scan/{scanId}/complete-assets?sort='
                   '-1&dir=-1&startIndex=-1&results=500&table-id=scan-complete-assets',
                   headers=self.headers, verify=self.verify).json()
        pages = ceil(int(resp['totalRecords']) / 500)
        for i in range(pages):
            resp = get(f'{self.nexpose_url}/data/asset/scan/{scanId}/complete-assets?sort='
                       f'-1&dir=-1&startIndex={500 * i}&results=500&table-id=scan-complete-assets',
                       headers=self.headers, verify=self.verify).json()['records']
            for node in resp:
                nodes.update({node['ipAddress']: node['nodeID']})
        return nodes


class Vulnerabilities:
    def __init__(self, Ses):
        self.nexpose_url = Ses.nexpose_url
        self.headers = Ses.login()
        self.verify = Ses.verify

    def vulnDescription(self, vulnId):
        """
        return vulnerability description by vulnerability id
        :param vulnId | for example vulnDescription(58116)
        :return: description(str)
        Example return 'The Axis2 administrator admin has a password that is set to thedefault value of axis2.
        As a result, anyone with access to the Axis2port can trivially gain full access to the machine via
        arbitrary remotecode execution.'

        """
        description = []
        resp = get(f'{self.nexpose_url}/vulnerability/vuln-summary.jsp?vulnid={vulnId}',
                   headers=self.headers, verify=self.verify)
        contents = resp.text
        soup = BeautifulSoup(contents, 'lxml').find_all('div', class_='remediation')
        for string in soup[0].stripped_strings:
            description.append(
                repr(string).replace('\\n       ', '').replace('\\n      ', '').replace("'", "").replace('"', ''))
        return ''.join(description)

    def vulnByNode(self, nodeId):
        """
        return vulnerability ids by node id
        :param nodeId: | for example vulnByNode(218037225)
        :return: vulnerabilities id(tuple)
        Example return (170659, 170658, 80948, 17889, 160815, 160803, 160802, 160808, 160825)
        """
        resp = get(f'{self.nexpose_url}/data/node/vulns/dyntable?printDocType=0&tableID=nodeVulnsTable&nodeID={nodeId}',
                   headers=self.headers, verify=self.verify)
        contents = resp.text
        soup = BeautifulSoup(contents, 'lxml').find_all('tr')
        vulnerabilities_id = []
        for so in soup:
            vulnerabilities_id.append(int(str(so).split('<td>')[1].split('</td>')[0]))
        return tuple(vulnerabilities_id)

    def vulnBySite(self, siteId):
        """
        return info about vulnerability by site
        :param siteId: vulnBySite(103)
        :return: vulnerabilities_info(dict)
        {vulnerability_id:[vulnerability_title, vulnerability_exploit]}

        Example return
        {
            95837: ['Microsoft SQL Server Obsolete Version', None],
            66070: ['Obsolete Debian GNU/Linux Version', None]
         }
        """
        vulnerabilities_info = {}
        resp = post(f'{self.nexpose_url}/data/vulnerability/filteredVulnerabilities',
                    data=(
                        'sort=-1&dir=-1&startIndex=-1&results=500&table-id=vulnerability-listing&searchCriteria=%7B'
                        '%22operator%22%3A%22AND%22%2C%22criteria%22%3A%5B%7B%22metadata%22%3A%7B%22fieldName%22%3A'
                        '%22SITE_NAME%22%7D%2C%22operator%22%3A%22IN%22%2C%22values%22%3A%5B%22'
                        f'{siteId}%22%5D%7D%5D%7D'), headers=self.headers, verify=self.verify).json()
        pages = ceil(int(resp['totalRecords']) / 500)
        for i in range(pages):
            resp = post(f'{self.nexpose_url}/data/vulnerability/filteredVulnerabilities',
                        data=(
                            f'sort=-1&dir=-1&startIndex={500 * i}&results=500&table-id=vulnerability-listing'
                            f'&searchCriteria=%7B '
                            '%22operator%22%3A%22AND%22%2C%22criteria%22%3A%5B%7B%22metadata%22%3A%7B%22fieldName%22%3A'
                            '%22SITE_NAME%22%7D%2C%22operator%22%3A%22IN%22%2C%22values%22%3A%5B%22'
                            f'{siteId}%22%5D%7D%5D%7D'), headers=self.headers, verify=self.verify).json()
            for vulner in resp['records']:
                if vulner['severity'] > 7:  # only critical
                    vulnerabilities_info.update({vulner['vulnID']: [vulner['title'], vulner['mainExploit']]})
        return vulnerabilities_info

    def assetVulners(self, vulnIds, assetsScan):
        IpName = {}
        resp = post(f'{self.nexpose_url}/data/vulnerability/proof',
                    data=(
                        f'sort=-1&dir=-1&startIndex=-1&results=500&table-id=vulnerability-proof&vulnid={vulnIds}'),
                    headers=self.headers, verify=self.verify).json()
        pages = ceil(int(resp['totalRecords']) / 500)
        for i in range(pages):
            resp = post(f'{self.nexpose_url}/data/vulnerability/proof',
                        data=(
                            f'sort=-1&dir=-1&startIndex={500 * i}&results='
                            f'500&table-id=vulnerability-proof&vulnid={vulnIds}'),
                        headers=self.headers, verify=self.verify).json()
            for ass in resp['records']:
                if str(ass['assetID']) in assetsScan:
                    IpName.update({ass['assetIP']: ass['assetName']})
        return IpName
