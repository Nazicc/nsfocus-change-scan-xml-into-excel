#!/usr/bin/env python
#coding=utf-8
from BeautifulSoup import BeautifulSoup
import urllib2
import re
import sys
import os
import glob
reload(sys)
sys.setdefaultencoding('utf-8')



def dig():
        #为了兼容linux 与windows，采用glob库
#        cmd = 'ls hosts/ | grep html > digPort.txt'
#        os.system(cmd)
#        fn = open('digPort.txt')
#        lines = fn.readlines()
#        fn.close()
        global dictVulPort
        lines = glob.glob('hosts/*.html')
        dictVulPort = {}

        for line in lines:
               #!!!BUG: avoid the different html has the same vulnerable information ,\
               #but the diff port BUG
               # we try to setdefault('', []).append() to avoid it
               line = line.split('\n')
               #line[0] = 'hosts/' + line[0]为linux shell过滤html文件专用
               #line[0] = 'hosts/' + line[0]
               print line[0]
               soupLine = BeautifulSoup(open(line[0]))
               #应该只有一个大的portwithvulnlist标签[0portwithvulnlist]
               tableLine = soupLine.findAll('div', {"id":'portwithvulnlist'})
               # print len(tableLine)
               #在大的portwithvulnlist中，我们找<tr class="even" or <tr class="odd",得到端口
               #但是<tr class="odd"><td colspan="4">主机 DZQH-MON1  的漏洞信息：</td></tr>不算，后续减1
               portLine = tableLine[0].findAll('tr',{"class":re.compile('(even)|(odd)')})
               # 如len(portLine)= 8,表示这个html有8个端口,减1是为了取出干扰项<tr class="odd">
               #<td colspan="4">主机 DZQH-MON1  的漏洞信息：</td></tr>
               port = range(0, len(portLine))
               #print portLine
               vul = range(0,len(portLine))

               for i in range(1,len(portLine)):
                       #在每个portLine[i]中，正则匹配端口，当然端口唯一，
                       #BeautifulSoup查找<a href="#tag50631" class="vul-vl">允许Traceroute
                       #探测</a>。。。。。。建立字典
                       port[i-1] = str(re.findall('<td>.{0,10}</td><td>.{0,10}</td><td>', str(portLine[i])))
                       port[i-1] = re.sub('[<td><\/td>]', '', port[i-1])
                       port[i-1] = re.sub('\]', '', port[i-1])
                       port[i-1] = re.sub('(\-)|(\')', '', port[i-1])
                       port[i-1] = re.sub('\[', '', port[i-1])
                       #现在页面1的所有port存在port[i]中了，共8个
                       #接下来找漏洞描述，每个port[i]存着若干个漏洞在vul[i]中
                       vul[i-1] = portLine[i].findAll('a',{"class":re.compile('vul-v.')})
                       #now， vul[i] = '[<a href="#tag50631" class="vul-vl">允许Traceroute
                       #探测</a>, <a href="#tag50638" class="vul-vl">ICMP timestamp请求响应漏洞</a>]'
                       for j in range(0,len(vul[i-1])):
                               vul[i-1][j] = re.sub('<a href="#tag.{0,10}" class="vul-v.">', '', str(vul[i-1][j]))
                               #for the bug Apache HTTP Server &quot;mod_proxy&quot;反向代理安全
                               #限制绕过漏洞
                               #we should trans the &quot; to "
                               vul[i-1][j] = re.sub('&quot;', '"', str(vul[i-1][j]))
                               vul[i-1][j] = (re.sub('</a>', '', vul[i-1][j])).decode('string-escape')

                               #现在，vul[i]为list类型，里面存储着若干对应port[i]的漏洞，开始建字典
                               #对于只有端口，或只有漏洞的，我们不加入字典,也不影响
                               #这里我们使用了list作为value，从而避免了same key,diff value's BUG
                               # remember the dictVulPort 对所有的hosts/xxxx.html来说是全局的
                               # all the html use the same dictVulPort
                               dictVulPort.setdefault(vul[i-1][j],[]).append(port[i-1])
        return dictVulPort
