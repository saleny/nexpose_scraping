from ..nexpose.nexpose_py import Scanner, Vulnerabilities, Session
from ..nexpose.reports import Reporter


user = ('username', 'password')
url = 'https://nexpose_url:port'
cert = '/path/to/CA/cert'

session = Session(user[0], user[1], url, verify=cert)
scan = Scanner(session)
vuln = Vulnerabilities(session)
rep = Reporter(scan, vuln, 'report.xlsx')
rep.create_report('xlsx')

