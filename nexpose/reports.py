from openpyxl import Workbook
from openpyxl.styles import Font, Alignment


class Reporter:
    def __init__(self, scanner, vulnerabilities):
        self.vulnerabilities = vulnerabilities
        self.scanner = scanner

    def write_excel(self):
        scanner = self.scanner
        vulnerabilities = self.vulnerabilities
        lastScanSite = scanner.lastScanSiteId()
        siteId = list(lastScanSite.keys())[2]
        lastScan = scanner.lastScanBySiteId(siteId)
        vulnIds = vulnerabilities.activeVulnBySite(siteId)
        assetsScan = scanner.assetsByScan(lastScan[0])
        nodesScan = scanner.nodesByScan(lastScan[1])
        workbook = Workbook()
        workbook.create_sheet(title='Vulnerabilities', index=0)
        sheet = workbook['Vulnerabilities']
        sheet.column_dimensions['A'].width = 42
        sheet.column_dimensions['B'].width = 110
        sheet.column_dimensions['C'].width = 42
        sheet['A1'], sheet['B1'], sheet['C1'] = 'Vulnerability', 'Solutions', 'Asset'
        sheet.auto_filter.ref = 'A1:C1'
        sheet['A1'].font, sheet['B1'].font, sheet['C1'].font = Font(bold=True), Font(bold=True), Font(
            bold=True)
        sheet['A1'].alignment, sheet['B1'].alignment, sheet['C1'].alignment = Alignment(horizontal="center"), \
                                                                               Alignment(horizontal="center"), \
                                                                               Alignment(horizontal="center")
        num, sd = 0, [2]
        for i in list(vulnIds.keys()):
            sheet[f'A{num + 2}'] = vulnIds[i][0]
            sheet[f'A{num + 2}'].alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            if vulnIds[i][1] is not None:
                sheet[f'A{num + 2}'].font = Font(color='4169E1', bold=True)
            keysAssetVuln = vulnerabilities.assetVulners(i, assetsScan)
            if keysAssetVuln == {}:
                sheet[f'A{num + 2}'] = None
                continue
            else:
                for j in list(keysAssetVuln.keys()):
                    sheet[f'C{num + 2}'] = f'{j} ({keysAssetVuln[j]})'
                    print(j)
                    try:
                        if i in vulnerabilities.vulnByNode(nodesScan[j]):
                            sheet[f'C{num + 2}'].font = Font(color='FF0000', bold=True)
                    except KeyError:
                        continue
                    finally:
                        num = num + 1
            sd.append(num + 2)
        print(sd)
        for i in range(len(sd) - 1):
            sheet.merge_cells(f'A{sd[i]}:A{sd[i + 1] - 1}')
            sheet.merge_cells(f'B{sd[i]}:B{sd[i + 1] - 1}')
        workbook.save('rep.xlsx')

    def create_report(self, report_type):
        if report_type == 'xls':
            self.write_excel()
        else:
            print('unknown type')

