from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from django.contrib.auth import login
from .forms import UserForm

from django.http import HttpResponse
from django.contrib.auth import authenticate
from .forms import LoginForm

from django.contrib.auth import logout

import logging
logger = logging.getLogger('django')

import hashlib
import time
import os
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent

username = ''
ip = ''

# Create your views here.

def home(request):
    return render(request, 'home.html')



def signup(request):
    if request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            new_user = User.objects.create_user(**form.cleaned_data)
            login(request, new_user)
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0]
            else:
                ip = request.META.get('REMOTE_ADDR')
            print('logger = ', logger, '  __name__ = ', __name__)
            logger.debug('[MODULE] = {}   [IP] = {}   [USER NAME] = {}'.format('SIGN UP', ip, new_user))

            #로그 정보 해시하기
            now = time.localtime()
            now = "%04d/%02d/%02d %02d:%02d:%02d" % (now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec)
            userinfo = '[TIME]'+ now + '   [IP]' + ip + '   [USER]' + username

            print(userinfo)
            userinfo_1 = hashlib.sha256(userinfo.encode())
            finalinfo = (userinfo_1.hexdigest())

            hash_txt = os.path.join(BASE_DIR, 'logs') + "/hash"
            text = open(hash_txt, 'a')
            data = (userinfo + '\n'+  '[SHA256] = '  + finalinfo + '\n')
            text.write(data)
            text.close()
            
            return redirect('home')
            
    else:
        form = UserForm()
        return render(request, 'user_new.html')


def signin(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        global username, ip
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username = username, password = password)

        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')

        if user is not None:
            login(request, user)
            logger.debug('[MODULE] = {}   [IP] = {}   [USER NAME] = {}'.format('SIGN IN', ip, username))

            #로그정보 해시하기
            now = time.localtime()
            now = "%04d/%02d/%02d %02d:%02d:%02d" % (now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec)
            userinfo = '[TIME]'+ now + '   [IP]' + ip + '   [USER]' + username

            print(userinfo)
            userinfo_1 = hashlib.sha256(userinfo.encode())
            finalinfo = (userinfo_1.hexdigest())

            hash_txt = os.path.join(BASE_DIR, 'logs') + "/hash.txt"
            text = open(hash_txt, 'a')
            data = (userinfo + '\n'+  '[SHA256] = '  + finalinfo + '\n')
            text.write(data)
            text.close()

            return redirect('home')
            
        else:
            return HttpResponse('Login failed. Try again.')
    else:
        form = LoginForm()
        return render(request, 'user_login.html')




def signout(request):
    logout(request)
    global username, ip
    logger.debug('[MODULE] = {}    [IP] = {}   [USER NAME] = {}'.format('LOGOUT', ip, username))
    ip = ''
    username = ''
    return redirect('home')



def google(request):
    logger.debug('[MODULE] = {}   '.format('GOOGLE'))
    return render(request, 'google.html')