from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from DjangoSalt import settings

import requests
import json
from . import forms
from django.http import FileResponse
import ssl
import subprocess

@login_required
def index(request):
    if request.session.get('is_login', None):
        return redirect("/index/")
    return render(request, 'index.html', locals())


def acc_login(request):
    error_msg = ''
    if request.session.get('is_login', None):
        return redirect("/index/")
    if request.method == 'POST':
        username = request.POST.get('username', None)
        password = request.POST.get('password', None)
        #user是一个对象
        #验证
        user = authenticate(username=username, password=password)
        if user:
            #登录（已生成session）
            login(request, user)
            #如果有next值就获取next值，没有就跳转到首页
            return redirect(request.GET.get('next', '/salt/'))
        else:
            error_msg = '用户名或密码错误！'

    return render(request, 'login.html', {'error_msg': error_msg})

def acc_logout(request):
    logout(request)
    return redirect("/salt/login/")


context = ssl._create_unverified_context()

# 使用requests请求https出现警告，做的设置
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


salt_api = "https://10.251.249.234:8001/"


class SaltApi:
    def __init__(self, url):
        self.url = url
        self.username = "saltapi"
        self.password = "netinnet.2018"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36",
            "Content-type": "application/json"
        }
        self.params = {'client': 'local', 'fun': '', 'tgt': ''}
        # self.params = {'client': 'local', 'fun': '', 'tgt': '', 'arg': ''}
        self.login_url = salt_api + "login"
        self.login_params = {'username': self.username, 'password': self.password, 'eauth': 'pam'}
        self.token = self.get_data(self.login_url, self.login_params)['token']
        self.headers['X-Auth-Token'] = self.token

    def get_data(self, url, params):
        send_data = json.dumps(params)
        request = requests.post(url, data=send_data, headers=self.headers, verify=False)
        response = request.json()
        result = dict(response)
        return result['return'][0]

    def salt_command(self, tgt, method, arg=None):
        if arg:
            params = {'client': 'local', 'fun': method, 'tgt': tgt, 'arg': arg}
        else:
            params = {'client': 'local', 'fun': method, 'tgt': tgt}
        print ('命令参数: ', params)
        result = self.get_data(self.url, params)
        return result


def saltstack(request):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))
    if not request.user.is_superuser:
        return HttpResponse("你没有权限访问这个页面！")
    salt = SaltApi(salt_api)
    if request.method == "POST":
        form = forms.UserForm(request.POST)
        if form.is_valid():
            salt_client = form.cleaned_data['saltClient']
            salt_params = form.cleaned_data['saltParams']
            salt_method = 'cmd.run'
            result = salt.salt_command(salt_client, salt_method, salt_params)
            for i in result.keys():
                print (i)
                print (result[i])
                info2 = result[i]
    return render(request, 'salt_page.html', locals())

"""
def download(request):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))
    file = open('/root/test.py', 'rb')
    response = FileResponse(file)
    response['Content-Type']='application/octet-stream'
    response['Content-Disposition']='attachment;filename="test.py"'
    return response
"""

def download(request):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))
    if request.method == "POST":
        form = forms.LogNameForm(request.POST)
        if form.is_valid():
            loglist = form.cleaned_data['loglist']
            result = subprocess.check_output(["ls", "/root/share/" + loglist])
            info3 = bytes.decode(result)
        form1 = forms.DownloadForm(request.POST)
        if form1.is_valid():
            projectname = form1.cleaned_data['projectname']
            filename1 = form1.cleaned_data['filename']
            file = open('/root/share/' + projectname + '/' + filename1, 'rb')
            response = FileResponse(file)
            response['Content-Type']='application/octet-stream'
            response['Content-Disposition']='attachment;filename=''{}'.format(filename1)
            return response
    return render(request, 'download.html', locals())
"""
def SQLDownload(request):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))
    if request.method == "POST":
        form = forms.SQLListForm(request.POST)
        if form.is_valid():
            sqllist = form.cleaned_data['sqllist']
            p1 = subprocess.Popen(['ls', '/root/sql_backup'], stdout=subprocess.PIPE)
            p2 = subprocess.Popen(['grep', sqllist], stdin=p1.stdout, stdout=subprocess.PIPE)
            out,err = p2.communicate()
            info = bytes.decode(out)
            print(info)
    if request.method == "POST":
        form1 = forms.SQLNameForm(request.POST)
        if form1.is_valid():
            sqlname = form1.cleaned_data['sqlname']
            print (sqlname)
            file = open('/root/sql_backup/' + sqlname, 'rb')
            print(file)
            response = FileResponse(file)
            response['Content-Type']='application/octet-stream'
            response['Content-Disposition']='attachment;filename=''{}'.format(sqlname)
            return response
    return render(request, 'SQLDownload.html', locals())
"""


def nginx_switch(request):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))
    if not request.user.is_superuser:
        return HttpResponse("你没有权限访问这个页面！")
    salt = SaltApi(salt_api)
    salt_client = {'yoya-nginx-1','yoya-nginx-2','iZ231v9zzqvZ'}
    salt_params_yoya = 'sh switch_dy_nginx_web.sh 1'
    salt_method = 'cmd.run'
    if request.method == "POST":
        if 'reload' in request.POST:
            salt_params_reload = 'service nginx reload'
            for i in salt_client:
                result = salt.salt_command(i, salt_method, salt_params_reload)
                for a in result.keys():
                    print (a)
                    #print (result[a])
                    info = result[a]
                print(info)
        if '1' in request.POST:
            salt_params_dy = 'sh switch_dy_nginx_web.sh 1'
            for i in salt_client:
                result = salt.salt_command(i, salt_method, salt_params_dy)
                for a in result.keys():
                    print (a)
                    #print (result[a])
                    info = result[a]
                print(info)
        if '2' in request.POST:
            salt_params_dy = 'sh switch_dy_nginx_web.sh 2'
            for i in salt_client:
                result = salt.salt_command(i, salt_method, salt_params_dy)
                for a in result.keys():
                    print (a)
                    #print (result[a])
                    info = result[a]
                print(info)
        if '3' in request.POST:
            salt_params_dy = 'sh switch_dy_nginx_web.sh 3'
            for i in salt_client:
                result = salt.salt_command(i, salt_method, salt_params_dy)
                for a in result.keys():
                    print (a)
                    #print (result[a])
                    info = result[a]
                print(info)
        if '4' in request.POST:
            salt_params_yoya = 'sh switch_yoya_nginx_web.sh 1'
            for i in salt_client:
                result = salt.salt_command(i, salt_method, salt_params_yoya)
                for a in result.keys():
                    print (a)
                    info = result[a]
                print(info)
        if '5' in request.POST:
            salt_params_yoya = 'sh switch_yoya_nginx_web.sh 2'
            for i in salt_client:
                result = salt.salt_command(i, salt_method, salt_params_yoya)
                for a in result.keys():
                    print (a)
                    info = result[a]
                print(info)    
        if '6' in request.POST:
            salt_params_yoya = 'sh switch_yoya_nginx_web.sh 3'
            for i in salt_client:
                result = salt.salt_command(i, salt_method, salt_params_yoya)
                for a in result.keys():
                    print (a)
                    info = result[a]
                print(info)
        if '7' in request.POST:
            salt_params_all = 'sh switch_all_nginx_web.sh 1'
            for i in salt_client:
                result = salt.salt_command(i, salt_method, salt_params_all)
                for a in result.keys():
                    print (a)
                    info = result[a]
                print(info)
        if '8' in request.POST:
            salt_params_all = 'sh switch_all_nginx_web.sh 2'
            for i in salt_client:
                result = salt.salt_command(i, salt_method, salt_params_all)
                for a in result.keys():
                    print (a)
                    info = result[a]
                print(info)
        if '9' in request.POST:
            salt_params_all = 'sh switch_all_nginx_web.sh 3'
            for i in salt_client:
                result = salt.salt_command(i, salt_method, salt_params_all)
                for a in result.keys():
                    print (a)
                    info = result[a]
                print(info)
    return render(request, 'nginx_switch.html', locals())
