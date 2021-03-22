from requests import post, get


class Requests:
    def __init__(self, url, headers, verify=False):
        self.url = url
        self.headers = headers
        self.verify = verify

    def _post(self, method, data):
        return post(f'{self.url}/{method}',
                    data=data, headers=self.headers, verify=self.verify)

    def _get(self, method):
        return get(f'{self.url}/{method}', headers=self.headers, verify=self.verify)