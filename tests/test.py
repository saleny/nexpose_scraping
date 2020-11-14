from ..nexpose import scraping as np, reports as rp

baseUrl = 'https://nexposeUrl'
user = np.UserData('username', 'password')
session = np.ConnectSession(userData=user, baseUrl=baseUrl)
headers = session.login()
scanner = np.Scanner(nexposeUrl=baseUrl, headers=headers)
reporter = rp.Reporter(scanner=scanner)
reporter.create_report('xls')
session.logout()

