from django.shortcuts import render, redirect
from .models import * 
from django.contrib import messages
from django.db.models import Count
import bcrypt

## Register & Login
def index(request):
    return render(request, 'index.html')

def register(request):
    if request.method == "POST":
        errors = User.objects.reg_validator(request.POST)
        if errors:
            for value in errors.values():
                messages.error(request, value)
            return redirect('/')

        hashed_pw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt()).decode()
        user = User.objects.create(
            first_name = request.POST['first_name'],
            last_name = request.POST['last_name'],
            email = request.POST['email'],
            password = hashed_pw
        )
        request.session['user_id'] = user.id
        return redirect('/groups')
    return redirect('/')

def login(request):
    if request.method == "POST":
        user = User.objects.filter(email=request.POST['email'])
        if user:
            user = user[0]      
            if bcrypt.checkpw(request.POST['password'].encode(), user.password.encode()):
                request.session['user_id'] = user.id
                return redirect('/groups')
        messages.error(request, "Email or password is incorrect")
    return redirect('/')
    

def groups(request):
    if 'user_id' not in request.session:
        # messages.error(request, "You need to register or login!")
        return redirect('/')
        
    context = {
        'current_user': User.objects.get(id=request.session['user_id']),
        # 'all_groups': Group.objects.all(),
        'all_groups': Group.objects.all().order_by('-users_that_joined'),
        'group_count': Group.objects.count(),
    }
    return render(request, "groups.html", context)

def logout(request):
    request.session.flush()
    # request.session.clear()
    return redirect('/')

# FGROUP ROUTES BELOW
def create_group(request):
    if 'user_id' not in request.session:
        return redirect('/')
    if request.method == "POST":
        errors = Group.objects.group_validator(request.POST)
        if errors:
            for value in errors.values():
                messages.error(request, value)
            return redirect('/groups')

        user = User.objects.get(id=request.session['user_id'])
        group = Group.objects.create(
            name = request.POST['name'],
            description = request.POST['description'],
            member = user
        )
        # Group creator automatically becomes the first member of the group,     
        user.groups_entered.add(group)
        messages.success(request, "Group Create")
        return redirect('/groups')
    return redirect('/groups')

def show_group(request, group_id):
    context = {
        'one_group': Group.objects.get(id=group_id),
        'current_user': User.objects.get(id=request.session['user_id']),
        'all_users': User.objects.all()
    }
    return render(request, "group.html", context)

def add_membership(request, group_id):
    if 'user_id' not in request.session:
        return redirect('/')
    if request.method == 'POST':
        one_group = Group.objects.get(id=group_id)
        current_user = User.objects.get(id=request.session['user_id'])
        one_group.users_that_joined.add(current_user)
        # current_user.groups_entered.add(one_group)
    return redirect(f'/group/{group_id}')

def remove_membership(request, group_id):
    if 'user_id' not in request.session:
        return redirect('/')
    if request.method == 'POST':
        one_group = Group.objects.get(id=group_id)
        current_user = User.objects.get(id=request.session['user_id'])
        one_group.users_that_joined.remove(current_user)
        # current_user.groups_joined.add(one_group)
    return redirect(f'/group/{group_id}')   

def delete_group(request, group_id):
    group_to_delete = Group.objects.get(id=group_id)
    group_to_delete.delete()

    return redirect('/groups')
