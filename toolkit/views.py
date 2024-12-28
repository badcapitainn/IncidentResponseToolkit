from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from .forms import RegisterForm
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required


@csrf_exempt
@login_required(login_url='login')
def dashboard(request):
    context = {}
    template = '../templates/toolkit/dashboard.html'
    return render(request, template, context)


@csrf_exempt
def user_login(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    else:
        if request.method == 'POST':
            username = request.POST['username']
            password = request.POST['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid username or password.')
        context = {}
        template = '../templates/toolkit/login.html'
        return render(request, template, context)


@csrf_exempt
def registration(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    else:

        form = RegisterForm()
        if request.method == 'POST':
            form = RegisterForm(request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, 'Your account has been created!')
                return redirect('login')

        context = {'form': form}
        template = '../templates/toolkit/registration.html'
        return render(request, template, context)


def user_logout(request):
    logout(request)
    return redirect('login')