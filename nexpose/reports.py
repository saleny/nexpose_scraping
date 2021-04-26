from openpyxl import Workbook
from openpyxl.styles import Font, Alignment


class Reporter:
    def __init__(self, scanner, vulnerabilities, name, current_scan=None, previous_scan=None, site_id=None):
        self.vulnerabilities = vulnerabilities
        self.scanner = scanner
        self.name = name
        self.current_scan = current_scan
        self.previous_scan = previous_scan
        self.site_id = site_id

    def writeToXlsx(self):
        scanner = self.scanner
        vulnerabilities = self.vulnerabilities
        if not self.current_scan or not self.previous_scan or not self.site_id:
            last_scan_site = scanner.last_scan_site_id()
            site_id = last_scan_site[1]
            last_scan = scanner.last_scan_by_site_id(site_id)
            assets_scan = scanner.assets_by_scan(last_scan[0])
            nodes_scan = scanner.nodes_by_scan(last_scan[1])
        else:
            assets_scan = scanner.assets_by_scan(self.current_scan)
            nodes_scan = scanner.nodes_by_scan(self.previous_scan)
            site_id = self.site_id
        vuln_ids = vulnerabilities.vuln_by_site(site_id)
        xlsx = Workbook()
        xlsx.create_sheet(title='Vulnerabilities', index=0)
        sheet = xlsx['Vulnerabilities']
        sheet.column_dimensions['A'].width = 20
        sheet.column_dimensions['B'].width = 100
        sheet.column_dimensions['C'].width = 50
        sheet.column_dimensions['D'].width = 42
        sheet['A1'], sheet['B1'], sheet['C1'], sheet['D1'] = 'Vulnerability', 'Descriptions', 'Solutions', 'Asset'
        sheet.auto_filter.ref = 'A1:D1'
        sheet['A1'].font = sheet['B1'].font = sheet['C1'].font = Font(bold=True)
        sheet['A1'].alignment = sheet['B1'].alignment = sheet['C1'].alignment = Alignment(horizontal="center")
        num, sd = 0, [2]
        for i in list(vuln_ids.keys()):
            sheet[f'A{num + 2}'] = vuln_ids[i][0]
            sheet[f'B{num + 2}'] = vulnerabilities.vuln_description(i)
            sheet[f'A{num + 2}'].alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            sheet[f'B{num + 2}'].alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            if vuln_ids[i][1] is not None:
                sheet[f'A{num + 2}'].font = Font(color='4169E1', bold=True)
            keys_asset_vuln = vulnerabilities.asset_vulners(i, assets_scan)
            if keys_asset_vuln == {}:
                sheet[f'A{num + 2}'] = None
                continue
            else:
                for j in list(keys_asset_vuln.keys()):
                    sheet[f'D{num + 2}'] = f'{j} ({keys_asset_vuln[j]})'
                    try:
                        if i in vulnerabilities.vuln_by_node(nodes_scan[j]):
                            sheet[f'D{num + 2}'].font = Font(color='FF0000', bold=True)
                    except KeyError:
                        continue
                    finally:
                        num += 1
            sd.append(num + 2)
        for i in range(len(sd) - 1):
            sheet.merge_cells(f'A{sd[i]}:A{sd[i + 1] - 1}')
            sheet.merge_cells(f'B{sd[i]}:B{sd[i + 1] - 1}')
            sheet.merge_cells(f'C{sd[i]}:C{sd[i + 1] - 1}')
        xlsx.save(f'{self.name}.xlsx')

    def create_report(self, report_type):
        if report_type == 'xlsx':
            self.writeToXlsx()
        else:
            print('unknown type')

