from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User, Friend

import re
import bcrypt
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

# Create your views here.
def index(request):
    # User.objects.all().delete()
    return render(request, "register_app/index.html")

def register(request):
    if request.method == "GET":
        return redirect('/')
    #variables for form information
    fname = request.POST['first_name'].lower()
    lname = request.POST['last_name'].lower()
    email = request.POST['email'].lower()
    password = request.POST['password'].encode()
    confirm_password = request.POST['confirm_password'].encode()
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())

    #registration validaation. try to break the registration process and add more validations
    wrong = False
    if len(fname) < 1:
        wrong = True
        messages.warning(request, "First name cannot be blank!")
    if not fname.isalpha():
        wrong = True
        messages.warning(request, "First name cannot contain numbers!")
    if len(lname) < 1:
        wrong = True
        messages.warning(request, "Last name cannot be blank!")
    if not lname.isalpha():
        wrong = True
        messages.warning(request, "Last name cannot contain numbers!")
    if len(email) < 1:
        wrong = True
        messages.warning(request, "Email cannot be blank!")
    if not EMAIL_REGEX.match(email):
        wrong = True
        messages.warning(request, "Emails are not valid!")
    email_list = User.objects.filter(email=email)
    if email_list:
        wrong = True
        messages.warning(request, "Email is already registered! ")
    if len(password) < 1 or len(password) < 8:
        wrong = True
        messages.warning(request, "Password cannot be blank and atleast 8 characters!")
    if confirm_password != password:
        wrong = True
        messages.warning(request, "Passwords must match!")
    if not password == password:
        wrong = True
        messages.warning(request, "Passwords do not match!")
    if wrong:
        return redirect('/')

    else:
        messages.success(request, "Congratulations you passed the registration process DOOFUS!")
        User.objects.create(first_name=request.POST['first_name'], last_name= request.POST['last_name'], email= request.POST['email'], password= hashed)
        print fname
        print lname
        print email
        print password
        print confirm_password
        print hashed
        return redirect('/')





def login(request):
    user_email=request.POST['user_email']
    email_list = User.objects.filter(email=user_email)
    password = request.POST['password']
    # password_list = User.objects.filter(password=password)
    num_results = len(email_list)
    print num_results
    if num_results == 0:
        messages.warning(request, "Email does not exist!")
        return redirect('/')
    if email_list:
        hashed = email_list[0].password
        print hashed
        #grabs hashed variable(holding our email_list[0].password) and compares it to the database pw
        if bcrypt.hashpw(password.encode(), hashed.encode()) == hashed.encode():
            request.session['id'] = email_list[0].id
            request.session['first_name'] = email_list[0].first_name
            print "Logged in!"
            return redirect('/friends')
        else:
            print "Wrong PW"
            return redirect('/')


def friends(request):
    user = User.objects.get (id = request.session['id'])
    friend_list = Friend.objects.all()
    user_list = User.objects.all()
    context = {
        "friends" : friend_list,
        "users" : user_list,
    }
    return render(request, "register_app/login.html", context)

def addfriend(request, id):
    user = User.objects.get(id=id)
    user_list = User.objects.filter(id = id)
    print user.first_name
    print user.email
    print "******************************"
    uid = request.POST['uid']
    print uid
    Friend.objects.create(user_id = uid)
    print "Added a new friend!"
    return redirect('/friends')

def user(request, id):
    # set user to id
    user = User.objects.get(id = id)
    # var user_list = to list of objects. filter out specific id
    user_list = User.objects.filter(id = id)
    # print user info for test
    print user.first_name
    print user.last_name
    print user.email
    context = {
        "users" : user_list,
    }
    return render(request, "register_app/user.html", context)

def remove(request, id):
    friend = User.objects.get(id = id)
    # friend_list =
    print friend.id
    print friend.first_name
    print "Removing your friend!"
    friend_list = Friend.objects.filter(user_id = friend).delete()
    return redirect('/friends')

def logout(request):
    request.session.clear()
    return redirect('/')
