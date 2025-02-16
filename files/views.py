from django.shortcuts import render,redirect
from django.http import HttpResponse
from .forms import ManagerForm
from . import paillier, AESCipher
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import authenticate
from .models import Employee, Medicine, Component, Log
from django.conf import settings
from django.core.mail import send_mail
import random, datetime
from django.contrib.auth.decorators import login_required
import random
from django.contrib import messages
from django.shortcuts import redirect, reverse
import logging
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
import os
import logging
import random  # ✅ Ensure random is imported
import string
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
from django.core.mail import send_mail
from django.contrib import messages
from files.models import Employee, Medicine
from django.conf import settings
from django.urls import get_resolver
from django.http import HttpResponseRedirect
from server.email_info import EMAIL_HOST_USER




# Set up logging for email errors
logger = logging.getLogger(__name__)


def employeeLogin(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        try:
            employee = Employee.objects.get(email=email)
            if check_password(password, employee.password):  # ✅ Correct hash verification
                login(request, employee)  
                return redirect(f"/employee/{employee.id}/")
            else:
                messages.error(request, "Invalid credentials.")
        except Employee.DoesNotExist:
            messages.error(request, "No such employee found.")

    return render(request, "files/employeeLogin.html")

def newPassword(request):
    return render(request, 'files/newPassword.html')

def managerLogin(request):
    logout(request)  # Ensure the previous session is cleared
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        try:
            user = User.objects.get(username=email)  # Get user by email
            if user.check_password(password):  # Check hashed password
                login(request, user)
                return redirect("managerDashboard")
            else:
                messages.error(request, "Invalid credentials.")
        except User.DoesNotExist:
            messages.error(request, "User not found.")

    return render(request, "files/managerLogin.html")


def managerRegister(request):
    if request.method == "POST":
        user_form = ManagerForm(request.POST)
        medicine = request.POST.get("medicine", "").strip()

        if user_form.is_valid():
            user = user_form.save(commit=False)
            username = user_form.cleaned_data.get("username", "defaultuser")
            password = user_form.cleaned_data.get("password", "defaultpassword123")
            user.set_password(password)
            user.save()

            try:
                key_size = 256  # ✅ Ensure integer key size
                print(f"🔍 Debug: Type of key_size = {type(key_size)}, Value = {key_size}")

                # ✅ Generate keypair (Fix: Extract 'n' from PublicKey object)
                priv, pub_obj = paillier.generate_keypair(key_size)
                pub = int(pub_obj.n)  # ✅ Extract integer from PublicKey object

                print(f"🔍 Debug: Type of pub = {type(pub)}, Value = {pub}")  # ✅ Now pub is an integer

                priv1, priv2 = priv.get_list()  # Extract private key parts

                aes_key = AESCipher.gen_key()

                file_key = str(password)
                while len(file_key) < 32:
                    file_key += str(random.randint(0, 9))
                file_key = file_key.encode("UTF-8")

                encrypted_medicine = AESCipher.encrypt(medicine, aes_key).hex()
                med, created = Medicine.objects.get_or_create(manager=user, medicine_name=encrypted_medicine)

                # ✅ Ensure manager.txt and employee.txt exist
                with open("manager.txt", "w") as f:
                    f.write(f"{pub}\n{priv1}\n{priv2}\n{aes_key.hex()}")

                with open("employee.txt", "w") as f:
                    f.write(f"{pub}\n{aes_key.hex()}")

                # ✅ Authenticate & login user
                user = authenticate(username=username, password=password)
                if user:
                    login(request, user)
                    return redirect("/addEmployee/")
                else:
                    messages.error(request, "Authentication failed.")
                    return render(request, "files/managerRegister.html", {"user_form": user_form})

            except Exception as e:
                logger.error(f"⚠️ Error during manager registration: {e}")
                messages.error(request, f"Registration failed due to an error: {e}")
                return render(request, "files/managerRegister.html", {"user_form": user_form})

    else:
        user_form = ManagerForm()

    return render(request, "files/managerRegister.html", {"user_form": user_form})
                                                          
login_required(login_url='files:manLog')

from django.urls import reverse, Resolver404, get_resolver


def addEmployee(request):
    """Add a new employee and send them login credentials via email."""

    # ✅ Debug - Check Available URLs
    try:
        available_urls = [name for name in get_resolver().reverse_dict.keys() if isinstance(name, str)]
        print(f"🔍 Available URL Names: {available_urls}")  

        resolved_url = reverse("files:addEmployee")  # ✅ Try resolving the URL
        print(f"🔍 Resolved URL for addEmployee: {resolved_url}")
    except Resolver404 as e:
        logger.error(f"⚠️ Reverse resolution failed: {e}")
        messages.error(request, "Internal error: URL resolution failed.")
        return redirect("files:managerDashboard")  

    user = request.user  # ✅ Get the logged-in manager
    print(f"🔍 DEBUG: Logged-in manager -> {user.username}")  

    # ✅ Check if the manager has a medicine assigned
    try:
        med = Medicine.objects.get(manager=user)
    except Medicine.DoesNotExist:
        messages.error(request, "No medicine assigned. Register a medicine first.")
        return redirect("files:managerDashboard")  

    if request.method == "POST":
        emp_name = request.POST.get("inputName", "").strip()
        emp_email = request.POST.get("inputEmail3", "").strip()

        if not emp_name or not emp_email:
            messages.error(request, "Employee name and email are required.")
            return render(request, "files/addEmployee.html")

        if Employee.objects.filter(email=emp_email).exists():
            messages.error(request, "An employee with this email already exists.")
            return render(request, "files/addEmployee.html")

        # ✅ Generate a secure random password
        random_password = "".join(random.choices(string.ascii_letters + string.digits, k=10))
        hashed_password = make_password(random_password)  

        try:
            emp = Employee.objects.create(
                email=emp_email,
                name=emp_name,
                manager_name=user.username,
                medicine_name=med.medicine_name,
                password=hashed_password,  
            )

            print(f"✅ Employee Created: {emp.email}")  
            messages.success(request, f"Employee '{emp_name}' added successfully.")

            # ✅ Send Login Credentials via Email
            subject = "Your DevMust Impex Employee Login Details"
            message = f"""
            Dear {emp_name},

            Your employee account has been created.

            ✅ Username: {emp_email}
            ✅ Password: {random_password} (Please change it after logging in)

            🔗 Login Here: http://127.0.0.1:8000/employeeLogin/

            Best Regards,  
            DevMust Impex Team
            """
            recipient_list = [emp_email]

            try:
                send_mail(subject, message, EMAIL_HOST_USER, recipient_list, fail_silently=False)
                messages.success(request, f"Login details sent to {emp_email}.")
                logger.info(f"✅ Email sent successfully to {emp_email}")
            except Exception as e:
                logger.error(f"❌ Email sending failed for {emp_email}. Error: {e}")
                messages.error(request, "Employee added, but email could not be sent.")

        except Exception as e:
            logger.error(f"❌ Error creating employee {emp_email}: {e}")
            messages.error(request, f"Failed to add employee. Error: {e}")

        print("✅ DEBUG: Redirecting to addEmployee")
        return HttpResponseRedirect(reverse("files:addEmployee"))

    return render(request, "files/addEmployee.html")

login_required(login_url='files:manLog')
def logs(request):
    log = Log.objects.all()
    manager_file_path = "manager.txt"

    if not os.path.exists(manager_file_path):
        messages.error(request, "Error: manager.txt file is missing.")
        return render(request, "files/logs.html", {"values": []})

    try:
        with open(manager_file_path, "r") as file:
            all_lines = file.readlines()

        if len(all_lines) < 4:
            messages.error(request, "Error: manager.txt file is incomplete.")
            return render(request, "files/logs.html", {"values": []})

        pub = int(all_lines[0].strip())
        priv1 = int(all_lines[1].strip())
        priv2 = int(all_lines[2].strip())
        aes = bytes.fromhex(all_lines[3].strip())

        values = []
        ctr = 1
        for item in log:
            try:
                comp_name = bytes.fromhex(item.component_name)
                name = AESCipher.decrypt(aes, comp_name)
                quantity = paillier.decrypt(priv1, priv2, pub, int(item.component_quantity))
                cost = paillier.decrypt(priv1, priv2, pub, int(item.component_cost))

                values.append({
                    "ctr": ctr,
                    "created": item.created,
                    "ename": item.name,
                    "cname": name,
                    "quantity": quantity,
                    "cost": cost,
                })
                ctr += 1
            except Exception as e:
                logger.error(f"Decryption error for log entry {ctr}: {e}")

        return render(request, "files/logs.html", {"values": values})

    except Exception as e:
        logger.error(f"Error reading manager.txt: {e}")
        messages.error(request, f"Error reading manager.txt: {e}")
        return render(request, "files/logs.html", {"values": []})


login_required(login_url='files:manLog')


def display(request):
    manager_file_path = "manager.txt"

    if not os.path.exists(manager_file_path):
        messages.error(request, "Error: manager.txt file is missing.")
        return render(request, "files/display.html", {"values": []})

    try:
        with open(manager_file_path, "r") as file:
            all_lines = file.readlines()

        if len(all_lines) < 4:
            messages.error(request, "Error: manager.txt file is incomplete.")
            return render(request, "files/display.html", {"values": []})

        pub = int(all_lines[0].strip())
        priv1 = int(all_lines[1].strip())
        priv2 = int(all_lines[2].strip())
        aes = bytes.fromhex(all_lines[3].strip())

        try:
            user = User.objects.get(username=request.user.username)
        except User.DoesNotExist:
            messages.error(request, "Error: User not found.")
            return render(request, "files/display.html", {"values": []})

        try:
            med = Medicine.objects.get(manager=user)
        except Medicine.DoesNotExist:
            messages.error(request, "Error: No medicine assigned to this manager.")
            return render(request, "files/display.html", {"values": []})

        comp = Component.objects.filter(key=med)

        try:
            med_name = bytes.fromhex(med.medicine_name)
            med_name = AESCipher.decrypt(aes, med_name)
        except Exception as e:
            messages.error(request, f"Error decrypting medicine name: {e}")
            return render(request, "files/display.html", {"values": []})

        values = []
        ctr = 1

        for item in comp:
            try:
                comp_name = bytes.fromhex(item.component_name)
                name = AESCipher.decrypt(aes, comp_name)
                quantity = paillier.decrypt(priv1, priv2, pub, int(item.component_quantity))
                cost = paillier.decrypt(priv1, priv2, pub, int(item.component_cost))

                values.append({
                    "ctr": ctr,
                    "name": name,
                    "quantity": quantity,
                    "cost": cost,
                })
                ctr += 1
            except Exception as e:
                logger.error(f"Error processing component {item.id}: {e}")

        return render(request, "files/display.html", {"values": values, "med_name": med_name})

    except Exception as e:
        logger.error(f"Unexpected error in display function: {e}")
        messages.error(request, "An unexpected error occurred.")
        return render(request, "files/display.html", {"values": []})
def medicineName(request):
    return render(request, 'files/medicineName.html')    

login_required(login_url='files:empLog')
def addComponent(request, employee_id):

    element = Employee.objects.get(id=employee_id)
    medicine = Medicine.objects.get(medicine_name = element.medicine_name)
    file = open('employee.txt')
    all_lines = file.readlines()
    pub_key = int(all_lines[0])
    aes_key = all_lines[1]
    aes_key = bytes.fromhex(aes_key)

    med_name = medicine.medicine_name
    med_name = bytes.fromhex(med_name)
    med_name = AESCipher.decrypt(aes_key, med_name)

    if request.method == 'POST':
        employee_name = element.name
        date_field = datetime.datetime.now()
        name = request.POST['inputName']
        quantity = request.POST['inputQuantity']
        cost = request.POST['inputCost'] 

        new_name = AESCipher.encrypt(name, aes_key)
        new_name = new_name.hex()
        new_quantity = paillier.encrypt(pub_key, int(quantity))
        new_cost= paillier.encrypt(pub_key, int(cost)) 

        log = Log.objects.create(created=date_field, name = employee_name, component_name=new_name, component_quantity=new_quantity, component_cost=new_cost)
        log.save() 

        if Component.objects.filter(component_name=new_name).exists():
            obj = Component.objects.get(component_name=new_name)
            obj.component_quantity = paillier.e_add(pub_key, int(obj.component_quantity), int(new_quantity))
            obj.component_cost = paillier.e_add(pub_key, int(obj.component_cost), int(new_cost))
            obj.save()            
        else:
            form = Component.objects.create(key = medicine ,component_name=new_name, component_quantity=new_quantity, component_cost=new_cost)
            form.save() 
        # return render(request, 'files/employee.html')              

    return render(request, 'files/employee.html', {'employee':element, 'med_name': med_name})


@login_required(login_url='/managerLogin/')
def managerDashboard(request):
    return render(request, "files/managerDashboard.html")  # ✅ Ensure this template exists

# def register(request):
#     medicine_name = "Crocin"
#     file = open('manager.txt')
#     all_lines = file.readlines()
#     key = all_lines[3]
#     key = key[2:-1]
#     key = key.encode('UTF-8')
#     encrypt_msg = AESCipher.encrypt(medicine_name, key)

#     return HttpResponse("<h1>Holla modamustfakaa</h1>")

# def register_med(request):

#     if request.method =='POST':
#         medicine = Medicine(request.POST)
#         if medicine.is_valid():
#             medicine1 = medicine.save(commit=False)
#             priv,pub = paillier.generate_keypair(256)
#             a = priv.get_list()
#             priv1=a[0]
#             priv2 = a[1]
#             medicine1.privateKey_1 = priv1
#             medicine1.privateKey_2 = priv2
#             medicine1.publicKey = pub
#             medicine1.save()

#             return redirect('/home/')
#     else:
#         medicine = Medicine()
#     return render(request,'files/test.html',{'medicine':medicine})

# def add_component(request,med_id):
#     medic = Key.objects.get(id = med_id)
#     if request.method == 'POST':
#         constituent = Constituent(request.POST)
#         if constituent.is_valid():
#             constituent1 = constituent.save(commit=False)
#             quant = int(constituent1.component_quantity)
#             cost = int(constituent1.component_cost)
#             pub = int(medic.publicKey)
#             new_cost= paillier.encrypt(int(pub),cost)
#             new_quant = paillier.encrypt(pub,quant)
#             constituent1.component_quantity = new_quant
#             constituent1.component_cost = new_cost
#             constituent1.key = medic
#             constituent1.save()
#             return redirect('/home/')
#     else:
#         constituent = Constituent()
#     return render(request,'files/constituent.html',{'constituent':constituent,'medic':medic})

# def home(request):
#     items = Key.objects.all()

#     return render(request,'files/home.html',{'items':items})

# def retrieve_components(request,id):
#     medic = Key.objects.get(id = id)
#     compo = Component.objects.filter(key=medic)
#     a = {}
#     for c in compo:
#         c.component_cost = paillier.decrypt(int(medic.privateKey_1),int(medic.privateKey_2),int(medic.publicKey),int(c.component_cost))
#         c.component_quantity = paillier.decrypt(int(medic.privateKey_1), int(medic.privateKey_2), int(medic.publicKey),
#                                             int(c.component_quantity))
#         a[c.component_name] = [c.component_cost,c.component_quantity]

#     return render(request,'files/detail.html',{'a':a,'compo':compo})
