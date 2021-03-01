from ..nexpose.nexpose_py import Scanner, Vulnerabilities, UserData, Session
from ..nexpose.reports import Reporter


user = UserData('username', 'password')
url = 'https://nexpose_url:port'
cert = '/path/to/CA/cert'

session = Session(user, url, verify=cert)
scan = Scanner(session)
vuln = Vulnerabilities(session)
rep = Reporter(scan, vuln, 'report.xlsx')
rep.create_report('xlsx')

