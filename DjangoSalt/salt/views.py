from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from DjangoSalt import settings
from .Saltapi import SaltApi, salt_api

import json
from . import forms
from django.http import FileResponse
import subprocess

@login_required
def index(request):
    '''首页视图，判断是否已登陆'''
    if request.session.get('is_login', None):
        return redirect("/index/")
    return render(request, 'index.html', locals())


def acc_login(request):
    error_msg = ''
    '''判断是否登陆，登陆则跳转到首页'''
    if request.session.get('is_login', None):
        return redirect("/index/")
    if request.method == 'POST':    #POST方法验证，之后进行登陆账号密码验证
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


def saltstack(request):
    #进行登陆验证，未登陆跳转到登陆页面
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))
    #进行超级用户验证，非超级用户无法访问该页面
    if not request.user.is_superuser:
        return HttpResponse("你没有权限访问这个页面！")
    #导入Saltapi类
    salt = SaltApi(salt_api)
    if request.method == "POST":
        form = forms.UserForm(request.POST)
        if form.is_valid():
            salt_client = form.cleaned_data['saltClient']
            params1 = form.cleaned_data['saltParams1']
            params2 = form.cleaned_data['saltParams2']
            print(params1)
            print(params2)
            salt_params = 'sh updatetomcat.sh ftp://10.168.31.26/update/' + params1 + '/' + params2
            print (salt_params)
            salt_method = 'cmd.run'
            result = salt.salt_command(salt_client, salt_method, salt_params)
            for i in result.keys():
                print (i)
                print (result[i])
                info2 = result[i]
    if request.method == "POST":
        form = forms.SaltForm(request.POST)
        if form.is_valid():
            salt_client = form.cleaned_data['Client']
            salt_params =form.cleaned_data['Params']
            print(salt_client)
            print(salt_params)
            salt_method = 'cmd.run'
            result = salt.salt_command(salt_client, salt_method, salt_params)
            for i in result.keys():
                print (i)
                print (result[i])
                info3 = result[i]
    return render(request, 'salt_page.html', locals())


def download(request):
    #先执行shell脚本获取列表，str需要进行字符串转义：只要在后面加上.decode().strip()即可
    list = subprocess.check_output(["sh", "/root/service_share_list.sh"])
    list1 = list.decode().strip()
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))
    if request.method == "POST":
        form = forms.LogNameForm(request.POST)
        if form.is_valid():
            loglist = form.cleaned_data['loglist']
            result = subprocess.check_output(["ls", "/root/share/" + loglist])
            print(list1)
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
#该函数为数据库文件下载，暂时不可用，后续有需要可以使用
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
    #nginx切换判定返回的参数，执行相应的指令
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
