from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.core.mail import EmailMessage
from django.utils import timezone
from django.urls import reverse
from .models import *

@login_required # restrict page to authenticated users
def Home(request):
    return render(request, 'index.html')

def RegisterView(request):
    if request.method == 'POST':
        
        # getting user inputs from frontend
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        # validating user inputs
        user_data_has_error = False

        # validation checks

        if User.objects.filter(username=username).exists():
            user_data_has_error = True
            messages.error(request, 'Username already exists.')
        
        if User.objects.filter(email=email).exists():
            user_data_has_error = True
            messages.error(request, 'Email already registered.')  

        if len(password)<5:
            user_data_has_error=True
            messages.error(request,'Password must be at least 5 characters')

        if user_data_has_error:
            return redirect('register')
        
        else:
            # creating new user
            new_user = User.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                username=username,
                email=email,
                password=password
            )
            messages.success(request, 'Registration successful. You can now log in.')
            return redirect('login')
        
    return render(request, 'register.html')

def LoginView(request):

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        if not username or not password:
            messages.error(request, 'Please fill all the fields.')
            return redirect('login')
        
        # authenticate user
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request,user)
            return redirect('home')
        else:
            messages.error(request, 'Invalid username or password.')
            return redirect('login')

    return render(request, 'login.html') 

def LogoutView(request):
    logout(request)
    messages.success(request, 'You have been logged out.')
    return redirect('login')

def ForgotPassword(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)

            # create new reset id
            new_password_reset = PasswordReset(user=user)
            new_password_reset.save()

            # create password reset ur;
            password_reset_url = reverse('reset-password', kwargs={'reset_id': new_password_reset.reset_id})
            full_password_reset_url = f'{request.scheme}://{request.get_host()}{password_reset_url}'
            
            # email content
            email_body = f'Hi {user.first_name},\n\nYou requested a password reset. Click the link below to reset your password:\n\n{full_password_reset_url}\n\nIf you did not request this, please ignore this email.\n\nThanks,\nAuthentication Team'
            email_message = EmailMessage(
                subject='Password Reset Request',
                body=email_body,
                from_email=settings.EMAIL_HOST_USER,
                to=[email],
            )
            email_message.fail_silently=True
            email_message.send()

            return redirect('password-reset-sent', reset_id=new_password_reset.reset_id)

        except User.DoesNotExist:
            messages.error(request, 'No user found with this email address.')
            return redirect('forgot-password')

    return render(request, 'forgot_password.html')

def PasswordResetSent(request, reset_id):

    if PasswordReset.objects.filter(reset_id=reset_id).exists():
        return render(request, 'password_reset_sent.html')
    else:
        # redirect to forgot password page if invalid reset id
        messages.error(request, 'Invalid reset id.')
        return redirect('forgot-password')

    return render(request, 'password_reset_sent.html')

def ResetPassword(request, reset_id):

    try:
        password_reset_id = PasswordReset.objects.get(reset_id=reset_id)

        if request.method == 'POST':
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            passwords_have_error = False

            if password != confirm_password:
                passwords_have_error = True
                messages.error(request, 'Passwords do not match.')

            if len(password) < 5:
                passwords_have_error = True
                messages.error(request, 'Password must be at least 5 characters long.')

            # check to make sure link has not expired (valid for 10 minutes)
            expiration_time = password_reset_id.created_when + timezone.timedelta(minutes=10)
            if timezone.now() > expiration_time:
                passwords_have_error = True
                messages.error(request, 'Password reset link has expired. Please request a new one.')

                reset_id.delete()  # delete expired reset id

            # reset password if no errors
            if not passwords_have_error:
                user = reset_id.user
                user.set_password(password)
                user.save()

                # delete the used reset id
                reset_id.delete()

                messages.success(request, 'Password has been reset successfully. You can now log in.')
                return redirect('login')
            else:
                return redirect('reset-password', reset_id=reset_id.reset_id)

    
    except PasswordReset.DoesNotExist:
        
        # redirect to forgot password page if code does not exist
        messages.error(request, 'Invalid reset id')
        return redirect('forgot-password')
    

    return render(request, 'reset_password.html')