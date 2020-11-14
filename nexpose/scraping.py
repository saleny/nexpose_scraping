from math import ceil
from datetime import datetime
from requests import get, post
from bs4 import BeautifulSoup


class UserData:
    def __init__(self, userName, passwd):
        self.userName = userName
        self.pswd = passwd


class ConnectSession:
    def __init__(self, userData, baseUrl):
        self.userData = userData
        self.baseUrl = baseUrl
        self.headers = {
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest',
        }

    def login(self):
        data = f'nexposeccusername={self.userData.userName}&nexposeccpassword={self.userData.pswd}'
        resp = post(f'{self.baseUrl}/data/user/login', data=data,
                    headers=self.headers, verify=False)
        self.headers['nexposeCCSessionID'] = resp.json()['sessionID']
        self.headers['Cookie'] = f'i18next=en; time-zone-offset=-180; nexposeCCSessionID={resp.json()["sessionID"]}'
        return self.headers

    def logout(self):
        resp = post(f'{self.baseUrl}/logout.html', headers=self.headers, verify=False)
        return resp


class Scanner:
    def __init__(self, nexposeUrl, headers):
        self.baseUrl = nexposeUrl
        self.headers = headers

    def scan_history(self,
                     request_body):
        resp = post(f'{self.baseUrl}/data/scan/global/scan-history',
                    data=request_body,
                    headers=self.headers, verify=False)
        return resp.json()['records']

    def lastScanSiteId(self):  # return last siteID:scanID
        sd = []
        for scan in self.scan_history(request_body=
                                     'sort=-1&dir=-1&startIndex=-1&results=-1&table-id=global-completed-scans'):
            if scan['startedByCD'] == 'S':
                if datetime.fromtimestamp((scan['endTime'] // 1000)).strftime('%Y%m%d') == datetime.now().strftime(
                        '%Y%m%d'):
                    sd.append(scan['siteID'])
        return sd

    def lastScanBySiteId(self, siteId):  # return 2 past ScanIDs  исправить
        resp = post(f'{self.baseUrl}/data/scan/site/{siteId}',
                    data=('sort=-1&dir=-1&startIndex=-1&results=-1&table-id=site-completed-scans'),
                    headers=self.headers, verify=False).json()['records']
        return resp[0]['scanID'], resp[1]['scanID']

    def assetsByScan(self, scanId):  # return Assets by scan исправить в будущем прогон по страницам
        assets = []
        resp = get(f'{self.baseUrl}/data/asset/scan/{scanId}/complete-assets?sort=' \
                   '-1&dir=-1&startIndex=-1&results=500&table-id=scan-complete-assets',
                   headers=self.headers, verify=False).json()
        pages = ceil(int(resp['totalRecords']) / 500)
        for i in range(pages):
            resp = get(f'{self.baseUrl}/data/asset/scan/{scanId}/complete-assets?sort=' \
                       f'-1&dir=-1&startIndex={500 * i}&results=500&table-id=scan-complete-assets',
                       headers=self.headers, verify=False).json()
            for asset in resp['records']:
                assets.append(asset['assetID'])
        return assets

    def nodesByScan(self, scanId):
        nodes = {}
        resp = get(f'{self.baseUrl}/data/asset/scan/{scanId}/complete-assets?sort=' \
                   '-1&dir=-1&startIndex=-1&results=500&table-id=scan-complete-assets',
                   headers=self.headers, verify=False).json()
        pages = ceil(int(resp['totalRecords']) / 500)
        for i in range(pages):
            resp = get(f'{self.baseUrl}/data/asset/scan/{scanId}/complete-assets?sort=' \
                       f'-1&dir=-1&startIndex={500 * i}&results=500&table-id=scan-complete-assets',
                       headers=self.headers, verify=False).json()['records']
            for node in resp:
                nodes.update({node['ipAddress']: node['nodeID']})
        return nodes


class Vulnerabilities:

    def __init__(self, baseUrl, headers):
        self.baseUrl = baseUrl
        self.headers = headers

    def vulnerSolution(self, vulnId):  # исправить в будущем прогон по страницам
        resp = get(f'{self.baseUrl}/vulnerability/vuln-summary.jsp?vulnid={vulnId}',
                   headers=self.headers, verify=False)
        contents = resp.text
        soup = BeautifulSoup(contents, 'lxml').findAll('div', class_='remediationStepDetails')
        sd = []
        for so in soup:
            sd.append(so.find('p'))
        return sd

    def vulnByNode(nodeId, self):

        resp = get(f'{self.baseUrl}/data/node/vulns/dyntable?printDocType=0&tableID=nodeVulnsTable&nodeID={nodeId}',
                   headers=self.headers, verify=False)
        contents = resp.text
        soup = BeautifulSoup(contents, 'lxml').find_all('tr')
        vuln = []
        for so in soup:
            vuln.append(int(str(so).split('<td>')[1].split('</td>')[0]))
        return vuln

    def activeVulnBySite(self, siteId):  # исправить в будущем прогон по страницам
        vulnIds = {}
        resp = post(f'{self.baseUrl}/data/vulnerability/filteredVulnerabilities',
                    data=(
                        'sort=-1&dir=-1&startIndex=-1&results=500&table-id=vulnerability-listing&searchCriteria=%7B'
                        '%22operator%22%3A%22AND%22%2C%22criteria%22%3A%5B%7B%22metadata%22%3A%7B%22fieldName%22%3A'
                        '%22SITE_NAME%22%7D%2C%22operator%22%3A%22IN%22%2C%22values%22%3A%5B%22'
                        f'{siteId}%22%5D%7D%5D%7D'), headers=self.headers, verify=False).json()
        pages = ceil(int(resp['totalRecords']) / 500)
        for i in range(pages):
            resp = post(f'{self.baseUrl}/data/vulnerability/filteredVulnerabilities',
                        data=(
                            f'sort=-1&dir=-1&startIndex={500 * i}&results=500&table-id=vulnerability-listing&searchCriteria=%7B'
                            '%22operator%22%3A%22AND%22%2C%22criteria%22%3A%5B%7B%22metadata%22%3A%7B%22fieldName%22%3A'
                            '%22SITE_NAME%22%7D%2C%22operator%22%3A%22IN%22%2C%22values%22%3A%5B%22'
                            f'{siteId}%22%5D%7D%5D%7D'), headers=self.headers, verify=False).json()
            for vulner in resp['records']:
                if vulner['severity'] > 7:  # only critical
                    vulnIds.update({vulner['vulnID']: [vulner['title'], vulner['mainExploit'], vulner['vulnID']]})
        return vulnIds

    def assetVulners(self, vulnIds, assetsScan):  # исправить в будущем прогон по страницам
        IpName = {}
        resp = post(f'{self.baseUrl}/data/vulnerability/proof',
                    data=(
                        f'sort=-1&dir=-1&startIndex=-1&results=500&table-id=vulnerability-proof&vulnid={vulnIds}'),
                    headers=self.headers, verify=False).json()
        pages = ceil(int(resp['totalRecords']) / 500)
        for i in range(pages):
            resp = post(f'{self.baseUrl}/data/vulnerability/proof',
                        data=(
                            f'sort=-1&dir=-1&startIndex={500 * i}&results=500&table-id=vulnerability-proof&vulnid={vulnIds}'),
                        headers=self.headers, verify=False).json()
            for ass in resp['records']:
                if str(ass['assetID']) in assetsScan:
                    IpName.update({ass['assetIP']: ass['assetName']})
        return IpName

