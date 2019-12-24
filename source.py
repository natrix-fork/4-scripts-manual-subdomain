import requests
from urllib.parse import urlsplit
import json
from bs4 import BeautifulSoup


class Audit:

    def __init__(self, url):
        self.url = url
        self.domain = urlsplit(self.url).netloc

    def inspect_threat_crowd(self):
        response = requests.get(f' https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}')
        response = response.json()
        with open('threatcrowd.json', 'w') as f:
            json.dump(response, f)
        return response

    def inspect_hackertarget_hostsearch(self):
        response = requests.get(f'https://api.hackertarget.com/hostsearch/?q={self.domain}').text
        response = response.splitlines()
        result = []
        for line in response:
            domain, ip = line.split(',', 1)
            result.append({
                'domain': domain,
                'ip': ip
            })
        with open('hackertarget.json', 'w') as f:
            json.dump(result, f)
        return response

    def inspect_crt_sh(self):
        response = requests.get(f'https://crt.sh/?q={self.domain}').text
        soup = BeautifulSoup(response, 'html.parser')
        table = soup.select('td.outer')
        attrs = table[1].attrs
        if table[1].i:
            if table[1].i.getText() == 'None found':
                result = {
                    'success': False,
                    'message': 'None found'
                }
                with open('crt_sh.json', 'w') as f:
                    json.dump(result, f)

                return result
        else:
            table = table[1]
            table = table.table
            rows = table.find_all('tr')
            strings = []
            for row in rows:
                cols = row.find_all('td')
                cols = [x.text.strip() for x in cols]
                strings.append(cols)
            strings.pop(0)
            result = []
            for string in strings:
                result.append({
                    'crt.sh ID': string[0],
                    'Logged at': string[1],
                    'Not before': string[2],
                    'Not after': string[3],
                    'Issuer name': string[4]
                })
            with open('crt_sh.json', 'w') as f:
                json.dump(result, f)

            return result

    def inspect_certspotter(self):
        response = requests.get(f'https://certspotter.com/api/v0/certs?domain={self.domain}').json()
        with open('certspotter.json', 'w') as f:
            json.dump(response, f)
        return response
