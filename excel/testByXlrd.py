#!/usr/bin/env python
#coding=utf-8
from BeautifulSoup import BeautifulSoup
import urllib2
import re
import sys
import os
import xlwt
import xlrd
from xlrd import open_workbook
from xlwt import Workbook , easyxf
from xlutils.copy import copy
import digPort
from struct import pack
reload(sys) 
sys.setdefaultencoding('utf-8')

global soup
global table
global matrix
global tableNums
global tableNumsHigh
global tableNumsMed
global tableNumsLow
global templateName

#'string-escape'请参考http://bbs.chinaunix.net/thread-1301913-1-1.html
def convertCN(s):
        return s.decode('string-escape')

def replaceTD(text):
        str = ['<td valign="top">', '<br />', '</td>', '&lt;', '&gt;']
        for i in range(0,len(str)):
                # re.sub与re.replace的区别，前者全部替代，后者替代第一个出现的正则匹配
                text = re.sub(str[i], '', text)
        return text

def genMatrix(rows,cols):
        matrix = [['N/A' for col in range(cols)] for row in range(rows)]
        return matrix

# 取ip
def regex_ip(text):
        text = str(re.findall(r'>\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b<', text))
        text = re.sub('[\'\[\]<>]',' ',text)
        return text

# 取漏洞名称
def regex_desVul(text):
        text = re.sub('<a class="vul-v." href="#" onclick="return false;">', '', text)
        text = re.sub('&quot;', '"', text)
        text = (re.sub('</a>', '', text)).decode('string-escape')
        return text

def findVulnerableTable(filePath):
        global table
        global soup
        soup = BeautifulSoup(open(filePath))
        #每个漏洞被安排在一个table中
        table = range(0,)
        table = soup.findAll('table',{"class":'cmn_table plumb'}) 
        global tableNums
        tableNums =  len(table)
        #每个高危漏洞被安排在一个highTable中
        highTable = range(0,)
        highTable = soup.findAll('a',{"class":'vul-vh'})
        global tableNumsHigh
        tableNumsHigh = len(highTable)
        #中危
        medTable = range(0,)
        medTable = soup.findAll('a',{"class":'vul-vm'})
        global tableNumsMed
        tableNumsMed = len(medTable)
        #低危
        lowTable = range(0,)
        lowTable = soup.findAll('a',{"class":'vul-vl'})
        global tableNumsLow
        tableNumsLow = len(lowTable)

        tableMix = range(0,4)
        tableMix = [table, highTable, medTable, lowTable]
        return tableMix

def main():
        if os.path.exists('./index.html'):
                tableMix = findVulnerableTable('./index.html')
        else:
                print '文件不存在，请检查文件路径'
                return 

        matrix = genMatrix(tableNums,10)
        #digPV存储着｛端口描述：port｝的字典
        digPV = {}
        digPV = digPort.dig()
        #因为漏洞的描述信息在vul-vh, vul-vm, vul-vl中，比较麻烦，故单独处理
        for i in range(0,tableNumsHigh):
                matrix[i][3] = convertCN(regex_desVul(str(tableMix[1][i])))
                matrix[i][5] = '高'
                matrix[i][3] =  re.sub('    ', '', matrix[i][3])
                #在字典digPV中索引key漏洞信息，填入value端口信息
                matrix[i][4] = '  '.join(digPV[matrix[i][3]])

        for i in range(0,tableNumsMed):
                matrix[i+tableNumsHigh][3] = convertCN(regex_desVul(str(tableMix[2][i])))
                matrix[i+tableNumsHigh][5] = '中'
                matrix[i+tableNumsHigh][3] =  re.sub('   ', '', matrix[i+tableNumsHigh][3])
                matrix[i+tableNumsHigh][4] =  '  '.join(digPV[matrix[i+tableNumsHigh][3]])
        
        for i in range(0,tableNumsLow):
                matrix[i+tableNumsHigh+tableNumsMed][3] = convertCN(regex_desVul\
                                                          (str(tableMix[3][i])))
                matrix[i+tableNumsHigh+tableNumsMed][5] = '低'
                matrix[i+tableNumsHigh+tableNumsMed][3] = re.sub('   ', '', \
                                                          matrix[i+tableNumsHigh+tableNumsMed][3])
                matrix[i+tableNumsHigh+tableNumsMed][4] =  '  '.join\
                                                 (digPV[matrix[i+tableNumsHigh+tableNumsMed][3]])

        # 存储ip在第[2]列，漏洞详细描述在[6]列, 解决方法存在[7]列
        for i in range(0,tableNums):
                matrix[i][2] = regex_ip(str(table[i]))
                lenTemp = table[i].findAll('td',{"valign":"top"})
                if (len(lenTemp) > 3):
                        matrix[i][6] = convertCN( replaceTD(str(table[i].findAll\
                                                ('td',{"valign":"top"})[1])))
                        s = convertCN( replaceTD(str(table[i].findAll('td',{"valign":"top"})[3])))
                        if len(s) > 32767:
                                matrix[i][7] = '漏洞解决方法字符太长，请直接阅读html网页'
                        else:
                                matrix[i][7] = s
                else:
                        matrix[i][6] = convertCN( replaceTD(str(table[i].findAll\
                                                 ('td',{"valign":"top"})[1])))
                        matrix[i][7] = '低危漏洞，注意即可'

        book = Workbook(encoding='utf-8')
        sheet1 = book.add_sheet('漏洞信息')
#        sheet1.col(0).width = 100
#        设置styleTitle，第0行
#        styleTitle = xlwt.XFStyle()
#        patternTitle = xlwt.Pattern()
#        patternTitle.pattern = xlwt.Pattern.SOLID_PATTERN
#        patternTitle.pattern_fore_colour = 0x0a
#        styleTitle.pattern = patternTitle
#        alignment = xlwt.Alignment()
#        alignment.horizontal = 'left'
#        fontTitle = xlwt.Font()
#        fontTitle.name = 'Times New Roman'
#        fontTitle.height = 250
#        fontTitle.width = 2000
#        fontTitle.bold = True
#        styleTitle.font = fontTitle
#        styleTitle.alignment = alignment

#        设置正文的单元格背景色
#        style = xlwt.XFStyle()
#        pattern = xlwt.Pattern()
#        pattern.pattern = xlwt.Pattern.SOLID_PATTERN
#        pattern.pattern_fore_colour = 0x32
#        alignment = xlwt.Alignment()
#        alignment.horizontal = 'left'
#        style.pattern = pattern
#        font = xlwt.Font()
#        font.name = 'Times New Roman'
#        font.height = 250
#        font.width = 2000
#        font.bold = True
#        style.font = font
#        style.alignment = alignment
        styles = (easyxf('pattern:pattern solid, fore_colour aqua;'
                         'align: vertical center, horizontal left;'
                         'font: bold true, colour black;'
                         'borders: top thin, bottom thin, left thin, right thin;'),
                  easyxf('pattern:pattern solid, fore_colour red;'
                         'align: vertical center, horizontal left;'
                         'font: bold true, colour black;'
                         'borders: top thin, bottom thin, left thin, right thin;'),
                  easyxf('pattern:pattern solid, fore_colour yellow;'
                         'align: vertical center, horizontal left;'
                         'font: bold true, colour black;'
                         'borders: top thin, bottom thin, left thin, right thin;'),
                  easyxf('pattern:pattern solid, fore_colour green;'
                         'align: vertical center, horizontal left;'
                         'font: bold true, colour black;'
                         'borders: top thin, bottom thin, left thin, right thin;')
                 )

        title = ['序号','系统平台','IP地址','漏洞信息','端口','级别','说明','解决方法','是否整改','整改反馈']
        for col in range(0,10):
                if (col == 0) or (col == 1) or (col == 4) or (col == 5):
                        sheet1.write(0,col,title[col],styles[0])
                        sheet1.col(col).width = 4096
                else :
                        sheet1.write(0,col,title[col],styles[0])
                        sheet1.col(col).width = 4096*3

        for row in range(1,tableNums+1):
                for col in range(0,10):
                        # 此处加unicode函数是为了避免error:'ascii' codec can't decode byte 0xe6 in
                        # position 23: ordinal not in range(128), 但是book = Workbook(encoding='utf-
                        # 8')可以实现相同功能                       
                        # sheet1.write(row,col,unicode(matrix[row-1][col]),style)
                        if (row < tableNumsHigh+1):
                                sheet1.write(row,col,matrix[row-1][col],styles[1])
                        if (tableNumsHigh < row < tableNumsHigh+tableNumsMed+1):
                                sheet1.write(row,col,matrix[row-1][col],styles[2])
                        if (tableNumsHigh+tableNumsMed < row < tableNums+1):
                                sheet1.write(row,col,matrix[row-1][col],styles[3])

        book.save('report.xls')

main()
