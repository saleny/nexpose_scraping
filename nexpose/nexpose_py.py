from special_requests import Requests
from datetime import datetime
from math import ceil
from bs4 import BeautifulSoup


class Session(Requests):
    def __init__(self, username: str, password: str, nexpose_url: str, verify=False):
        self.username = username
        self.password = password
        self.nexpose_url = nexpose_url
        self.verify = verify
        self.headers = {
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest'
        }
        super().__init__(self.nexpose_url, self.headers, verify=self.verify)

    def login(self) -> dict:
        data = f'nexposeccusername={self.username}&nexposeccpassword={self.password}'
        respose = super()._post('data/user/login', data)
        self.headers['nexposeCCSessionID'] = respose.json()['sessionID']
        self.headers['Cookie'] = f'i18next=en; time-zone-offset=-180; nexposeCCSessionID={respose.json()["sessionID"]}'
        return self.headers

    def logout(self) -> None:
        super()._get(f'{self.nexpose_url}/logout.html')


class Scanner(Requests):
    def __init__(self, active_session):
        super().__init__(active_session.nexpose_url, headers=active_session.headers, verify=active_session.verify)

    def scan_history(self, requestBody=None) -> list:
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
        return super()._post('data/scan/global/scan-history', requestBody).json()['records']

    def last_scan_site_id(self) -> tuple:
        """
        return site id(tuple) by scan history if scan is scheduled and scan completed is today.
        Example return: (328, 128, 201)
         """
        site_ids = list()
        for scan in self.scan_history(
                requestBody='sort=-1&dir=-1&startIndex=-1&results=-1&table-id=global-completed-scans'):
            if scan['startedByCD'] == 'S':
                if datetime.fromtimestamp((scan['endTime'] // 1000)).strftime('%Y%m%d') == datetime.now().strftime(
                        '%Y%m%d'):
                    site_ids.append(scan['siteID'])
        return tuple(site_ids)

    def last_scan_by_site_id(self, siteId):
        """
        :param siteId | identificator site, for example lastScanBySiteId(261)
        :return: scans
        return last scans id by site id if scan is scheduled
        Example return (2586647, 2586646, 2586598, 2586592, 2586589, 2586587, 2586580, 2586492, 2586418, 2586394)
        """
        scans = list()
        response = super()._post(f'data/scan/site/{siteId}',
                                'sort=-1&dir=-1&startIndex='
                                '-1&results=-1&table-id=site-completed-scans').json()['records']
        for scan in response:
            if scan['startedByCD'] == 'S':
                scans.append(scan['scanID'])
        return tuple(scans)

    def assets_by_scan(self, scanId) -> tuple:
        """
        return devices id by scan id
        :param scanId: | identificator site, for example assetsByScan(261)
        :return: tuple(devices id)
        """
        assets = list()
        response = super()._get(f'data/asset/scan/{scanId}/complete-assets?sort='
                               '-1&dir=-1&startIndex=-1&results=500&table-id=scan-complete-assets').json()
        pages = ceil(int(response['totalRecords']) / 500)
        for i in range(pages):
            response = super()._get(f'data/asset/scan/{scanId}/complete-assets?sort='
                                   '-1&dir=-1&startIndex=-1&results=500&table-id=scan-complete-assets').json()
            for asset in response['records']:
                assets.append(asset['assetID'])
        return tuple(assets)

    def nodes_by_scan(self, scanId) -> dict:
        """
        return nodes id by scan id
        :param scanId | identificator site, for example nodesByScan(2586534)
        :return dict(nodes) | return {ipaddress:node_id}
        Example return {'10.10.10.10': 218037225, '10.10.10.11': 218036746, '10.100.10.12': 218037223}
        """
        nodes = dict()
        response = super()._get(f'/data/asset/scan/{scanId}/complete-assets?sort='
                               '-1&dir=-1&startIndex=-1&results=500&table-id=scan-complete-assets').json()
        pages = ceil(int(response['totalRecords']) / 500)
        for i in range(pages):
            response = super()._get(f'/data/asset/scan/{scanId}/complete-assets?sort=-1&dir=-1&startIndex=-1&results'
                                   f'=500&table-id=scan-complete-assets').json()['records']
            for node in response:
                nodes.update({node['ipAddress']: node['nodeID']})
        return nodes


class Vulnerabilities(Requests):
    def __init__(self, active_session):
        super().__init__(active_session.nexpose_url, headers=active_session.headers, verify=active_session.verify)

    def vuln_description(self, vulnId) -> str:
        """
        return vulnerability description by vulnerability id
        :param vulnId | for example vulnDescription(58116)
        :return: description(str)
        Example return 'The Axis2 administrator admin has a password that is set to thedefault value of axis2.
        As a result, anyone with access to the Axis2port can trivially gain full access to the machine via
        arbitrary remotecode execution.'

        """
        description = list()
        response = super()._get(f'vulnerability/vuln-summary.jsp?vulnid={vulnId}')
        contents = response.text
        soup = BeautifulSoup(contents, 'lxml').find_all('div', class_='remediation')
        for string in soup[0].stripped_strings:
            description.append(
                repr(string).replace('\\n       ', '').replace('\\n      ', '').replace("'", "").replace('"', ''))
        return ''.join(description)

    def vuln_by_node(self, nodeId) -> tuple:
        """
        return vulnerability ids by node id
        :param nodeId: | for example vulnByNode(218037225)
        :return: vulnerabilities id(tuple)
        Example return (170659, 170658, 80948, 17889, 160815, 160803, 160802, 160808, 160825)
        """
        response = super()._get(f'/data/node/vulns/dyntable?printDocType=0&tableID=nodeVulnsTable&nodeID={nodeId}')
        contents = response.text
        soup = BeautifulSoup(contents, 'lxml').find_all('tr')
        vulnerabilities_id = list()
        for so in soup:
            vulnerabilities_id.append(int(str(so).split('<td>')[1].split('</td>')[0]))
        return tuple(vulnerabilities_id)

    def vuln_by_site(self, siteId) -> dict:
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
        vulnerabilities_info = dict()
        response = super()._post('/data/vulnerability/filteredVulnerabilities',
                                 'sort=-1&dir=-1&startIndex=-1&results=500&table-id=vulnerability-listing'
                                 '&searchCriteria=%7B%22operator%22%3A%22AND%22%2C%22criteria%22%3A%5B%7B%22metadata'
                                 '%22%3A%7B%22fieldName%22%3A%22SITE_NAME%22%7D%2C%22operator%22%3A%22IN%22%2C'
                                 f'%22values%22%3A%5B%22{siteId}%22%5D%7D%5D%7D').json()
        pages = ceil(int(response['totalRecords']) / 500)
        for i in range(pages):
            response = super()._post('/data/vulnerability/filteredVulnerabilities',
                                     'sort=-1&dir=-1&startIndex=-1&results=500&table-id=vulnerability-listing'
                                     '&searchCriteria=%7B%22operator%22%3A%22AND%22%2C%22criteria%22%3A%5B%7B'
                                     '%22metadata%22%3A%7B%22fieldName%22%3A%22SITE_NAME%22%7D%2C%22operator%22%3A'
                                     f'%22IN%22%2C%22values%22%3A%5B%22{siteId}%22%5D%7D%5D%7D').json()
            for vulner in response['records']:
                if vulner['severity'] > 7:  # only critical
                    vulnerabilities_info.update({vulner['vulnID']: [vulner['title'], vulner['mainExploit']]})
        return vulnerabilities_info

    def asset_vulners(self, vulnIds, assetsScan) -> dict:
        ip_name = dict()
        response = super()._post('data/vulnerability/proof',
                                 'sort=-1&dir=-1&startIndex=-1&results=500&table-id'
                                 f'=vulnerability-proof&vulnid={vulnIds}').json()
        pages = ceil(int(response['totalRecords']) / 500)
        for i in range(pages):
            response = super()._post('data/vulnerability/proof',
                                     'sort=-1&dir=-1&startIndex=-1&results=500&table-id'
                                     f'=vulnerability-proof&vulnid={vulnIds}').json()
            for ass in response['records']:
                if str(ass['assetID']) in assetsScan:
                    ip_name.update({ass['assetIP']: ass['assetName']})
        return ip_name
