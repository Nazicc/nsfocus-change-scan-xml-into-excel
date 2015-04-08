#!/usr/bin/env python
#coding=utf-8
from BeautifulSoup import BeautifulSoup
import urllib2
import re
import sys
import os
reload(sys) 
sys.setdefaultencoding('utf-8')

global soup
global table
global matrix
global tableNums
global tableNumsHigh
global tableNumsMed
global tableNumsLow
global file
global templateName

#请参考http://bbs.chinaunix.net/thread-1301913-1-1.html
def convertCN(s):
        return s.decode('string-escape')


def genMatrix(rows,cols):
        matrix = [[0 for col in range(cols)] for row in range(rows)]
#        for i in range(rows):
#                for j in range(cols):
#                        print matrix[i][j]
#                print '\n'
        return matrix


def writeIntoCsv(tag,file):
        file.write(tag)


def createTemplate(templateName):
        template = open(templateName,'w')
        for i in range(0,tableNums):
                for j in range(0,10):
                        template.write('<data[%s][%s]>' % (i,j))
                        template.write(',,')
        template.close()
# 取ip
def regex_host(text):
        text = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', text)
        return text[0]

# 取漏洞描述存列表text[0],漏洞解决方法存列表text[1]
def regex_desDetails(text):
        text = re.findall(r'<td valign="top">.*<\/td>', text)
        return text

# 取漏洞名称
def regex_desVul(text):
        text = str(re.findall('>.*<' , text))
        text = re.sub('[<>]','',text)
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
        print 'This py use the csv ,but not good, discard it'
        if os.path.exists('./index.html'):
                tableMix = findVulnerableTable('./index.html')
        else:
                print '文件不存在，请检查文件路径'
                return 

        matrix = genMatrix(tableNums,10)

        #因为漏洞的描述信息在vul-vh, vul-vm, vul-vl中，比较麻烦，故单独处理
        for i in range(0,tableNumsHigh):
                print i
                matrix[i][3] = convertCN(regex_desVul(str(tableMix[1][i])))
                matrix[i][5] = '高'


        for i in range(tableNumsHigh,tableNumsHigh+tableNumsMed):
                print i
                matrix[i][3] = convertCN(regex_desVul(str(tableMix[2][tableNumsHigh-i])))
                matrix[i][5] = '中'

        
        for i in range(tableNumsHigh+tableNumsMed,tableNums):
                print i
                matrix[i][3] = convertCN(regex_desVul(str(tableMix[3][tableNumsHigh+tableNumsLow-i])))
                matrix[i][5] = '低'
        
        # 存储ip在第[2]列，漏洞详细描述在[6]列, 解决方法存在[7]列
        for i in range(0,tableNums):
                matrix[i][2] = regex_host(str(table[i]))
                matrix[i][6] = soup.findAll('td',{"valign":"top"})[1]
                matrix[i][7] = soup.findAll('td',{"valign":"top"})[3]
#                matrix[i][6] = convertCN(regex_desDetails(str(table[i]))[0])
#                matrix[i][7] = convertCN(regex_desDetails(str(table[i]))[1])


        for i in range(0,tableNums):
#                print matrix[i][6]
#                print matrix[i][2]
#                 print '!!!!!IP!!!!!!!!!!!!!!!!!!!!!'
#                 print matrix[i][2]
#                 print '!!!!!IP!!!!!!!!!!!!!!!!!!!!!'
#                 print '*****漏洞说明*************************'
#                 print matrix[i][6]
#                 print '+++++漏洞说明+++++++++++++++++++++++++'
#                 print '####解决方法################################'
#                 print matrix[i][7]
#                 print '##########解决方法#############################'
                 print '^^^^^^^^^^^漏洞名称^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^'
                 print matrix[i][3]
                 print '^^^^^^^^^^^^漏洞名称^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^'
                 print '\r\n'
#                 print ':::::::::::::::::::::::::::::::::::::::::::::::::'

#        file = open('output.txt', 'w')
#        for row in range(0,tableNums):
#                for col in range(0,10):
#                        print col
#                        print row
#                        print matrix[row][col]
#                        print type(matrix[row][col])
#                        file.write(str(matrix[row][col]))
#                        file.write(',')
#                file.write('\r\n')
#        file.close()
        # 创建csv模版
        createTemplate('template.txt')
        
        fn = open('template.txt','r')
        temp = fn.read()
        for row in range(0,tableNums):
                for col in range(0,10):
                        temp = temp.replace(r'<data[%s][%s]>'%(row,col), str(matrix[row][col]) )
        fn.close()

        fn = open('read.txt', 'w')
        fn.write(temp)
        fn.close()
        cmd = 'mv read.txt read.csv'
        os.system(cmd)
        cmd = 'vim read.csv'
        os.system(cmd)
        cmd = 'set fileencoding=gb2312'
        os.system(cmd)
        cmd = ':wq'
        os.system(cmd)

#        for row in range(0,tableNums):
#                for col in range(0,10):
#                        print col
#                        print row
#                        print matrix[row][col]
#                        print type(matrix[row][col])
#                        file.write(str(matrix[row][col]))
#                        file.write(',')
#                file.write('\r\n')
        # 用martrix中的数据replace CSV模版
#         file.replace
#        nameThread = parse_text(nameThread)
#        print str(nameThread)
#        paraText = parse_text(para)
#        writeIntoCsv(paraText,file)


main()
