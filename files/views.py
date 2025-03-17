from django.shortcuts import render, redirect, reverse
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.urls import get_resolver
from django.core.mail import send_mail
import random, string, datetime, os, logging
from django.contrib.auth.models import User
from django.shortcuts import render
from django.contrib.auth import logout
from django.views.decorators.csrf import csrf_protect
from django.utils.timezone import now
from django.contrib.auth.hashers import make_password
from django.db import models
from django.shortcuts import get_object_or_404
from datetime import datetime
from django.utils import timezone
from django.shortcuts import render
from .models import Log, Employee


# 🔹 Import Paillier Encryption & AES Cipher for Secure Data Handling
from . import paillier, AESCipher

# 🔹 Import Models (Updated for Company Data Storage)
from files.models import Employee, DataRecord, Log  # ✅ Correct Import


# 🔹 Import Forms (Updated for Company Data Storage)
from .forms import ManagerForm, CompanyDataForm, DataRecordForm

# 🔹 Import Email Configuration
from server.email_info import EMAIL_HOST_USER


def home(request):
    return render(request, "files/home.html")  # Renders home.html


def logs(request):
    manager = request.user

    # ✅ Fetch logs for employees under the logged-in manager
    log_entries = Log.objects.filter(employee__manager=manager).order_by("-timestamp")

    return render(request, "files/logs.html", {"logs": log_entries})


def logout_view(request):
    """Logs out the user and redirects to the home page."""
    logout(request)
    return redirect("home")


# Set up logging for email errors
logger = logging.getLogger(__name__)


def employeeLogin(request):
    if request.method == "POST":
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "").strip()

        try:
            employee = Employee.objects.get(email=email)
            print(f"✅ Employee found: {email}")

            if check_password(
                password, employee.password
            ):  # ✅ Compare hashed password
                login(request, employee)
                print(f"✅ Login successful: {email}")
                return redirect(
                    f"/employee/{employee.id}/"
                )  # Change this to employee dashboard if needed
            else:
                print(f"❌ Incorrect password for {email}")
                messages.error(request, "Invalid credentials. Please try again.")
                return render(request, "files/employeeLogin.html")

        except Employee.DoesNotExist:
            print(f"❌ Employee not found: {email}")
            messages.error(request, "Invalid credentials. Please try again.")

    return render(request, "files/employeeLogin.html")


def newPassword(request):
    return render(request, "files/newPassword.html")


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


from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.shortcuts import render, redirect, reverse
from .models import CompanyData  # ✅ Ensure model is imported
from .forms import ManagerForm
from . import paillier, AESCipher
import random
import logging

logger = logging.getLogger(__name__)


@csrf_protect
def managerRegister(request):
    if request.method == "POST":
        user_form = ManagerForm(request.POST)
        company_name = request.POST.get("CompanyData", "").strip()

        if user_form.is_valid():
            user = user_form.save(commit=False)
            username = user_form.cleaned_data.get("username", "defaultuser")
            password = user_form.cleaned_data.get("password", "defaultpassword123")
            user.set_password(password)
            user.save()

            try:
                key_size = 256
                print(
                    f"🔍 Debug: Type of key_size = {type(key_size)}, Value = {key_size}"
                )

                priv, pub_obj = paillier.generate_keypair(key_size)
                pub = int(pub_obj.n)

                print(f"🔍 Debug: Type of pub = {type(pub)}, Value = {pub}")

                priv1, priv2 = priv.get_list()
                aes_key = AESCipher.gen_key()

                file_key = (
                    (password or "defaultpassword123")
                    .encode("utf-8")[:32]
                    .ljust(32, b"0")
                )  # ✅ Secure key

                encrypted_CompanyData = AESCipher.encrypt(
                    company_name, aes_key
                ).hex()  # ✅ Encrypt the input data

                # ✅ Correct get_or_create usage
                company_instance, created = CompanyData.objects.get_or_create(
                    manager=user, defaults={"company_name": encrypted_CompanyData}
                )

                with open("manager.txt", "w") as f:
                    f.write(f"{pub}\n{priv1}\n{priv2}\n{aes_key.hex()}")

                with open("employee.txt", "w") as f:
                    f.write(f"{pub}\n{aes_key.hex()}")

                user = authenticate(username=username, password=password)
                if user:
                    login(request, user)
                    return redirect(
                        reverse("files:addEmployee")
                    )  # ✅ Redirect properly
                else:
                    messages.error(request, "Authentication failed.")
                    return render(
                        request, "files/managerRegister.html", {"user_form": user_form}
                    )

            except Exception as e:
                logger.error(f"⚠️ Error during manager registration: {e}")
                messages.error(request, f"Registration failed due to an error: {e}")
                return render(
                    request, "files/managerRegister.html", {"user_form": user_form}
                )

    else:
        user_form = ManagerForm()

    return render(request, "files/managerRegister.html", {"user_form": user_form})


login_required(login_url="files:manLog")

from django.urls import reverse, Resolver404, get_resolver


def addEmployee(request):
    """Add a new employee and send login credentials via email."""

    # ✅ Ensure the manager is authenticated
    if not request.user.is_authenticated:
        messages.error(request, "You must be logged in to add employees.")
        return redirect("files:manLog")

    manager_user = request.user  # ✅ Get the logged-in manager

    # ✅ Get the company associated with the manager
    company_data = CompanyData.objects.filter(manager=manager_user).first()
    if not company_data:
        messages.error(request, "No company assigned. Register company data first.")
        return redirect("files:managerDashboard")

    # ✅ Debugging - Check Available URLs
    try:
        available_urls = [
            name for name in get_resolver().reverse_dict.keys() if isinstance(name, str)
        ]
        print(f"🔍 Available URL Names: {available_urls}")

        resolved_url = reverse("files:addEmployee")  # ✅ Try resolving the URL
        print(f"🔍 Resolved URL for addEmployee: {resolved_url}")
    except Resolver404 as e:
        logger.error(f"⚠️ Reverse resolution failed: {e}")
        messages.error(request, "Internal error: URL resolution failed.")
        return redirect("files:managerDashboard")

    print(f"🔍 DEBUG: Logged-in manager -> {manager_user.username}")

    if request.method == "POST":
        emp_name = request.POST.get("inputName", "").strip()
        emp_email = request.POST.get("inputEmail3", "").strip()

        # ✅ Ensure required fields are provided
        if not emp_name or not emp_email:
            messages.error(request, "Employee name and email are required.")
            return render(request, "files/addEmployee.html")

        # ✅ Check if the email already exists
        if Employee.objects.filter(email=emp_email).exists():
            messages.error(request, "An employee with this email already exists.")
            return render(request, "files/addEmployee.html")

        # ✅ Generate a secure random password
        random_password = "".join(
            random.choices(string.ascii_letters + string.digits, k=10)
        )
        hashed_password = make_password(
            random_password
        )  # 🔥 Hash password before storing

        try:
            # ✅ Create employee record with correct `manager` and `company`
            emp = Employee.objects.create(
                email=emp_email,
                name=emp_name,
                manager=manager_user,
                company=company_data,
                password=make_password(random_password),
            )

            print(f"✅ Employee Created: {emp.email}")
            messages.success(request, f"Employee '{emp_name}' added successfully.")

            # ✅ Send Login Credentials via Email
            subject = "Your SecureCloud Employee Login Details"
            message = f"""
            Dear {emp_name},

            Your employee account has been created.

            ✅ Username: {emp_email}
            ✅ Password: {random_password} (Please change it after logging in)

            🔗 Login Here: http://127.0.0.1:8000/employeeLogin/

            Best Regards,  
            SecureCloud Team
            """
            recipient_list = [emp_email]

            try:
                send_mail(
                    subject,
                    message,
                    settings.EMAIL_HOST_USER,
                    recipient_list,
                    fail_silently=False,
                )
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


login_required(login_url="files:manLog")


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

        # ✅ Ensure the manager exists
        try:
            user = request.user  # Directly using request.user
        except User.DoesNotExist:
            messages.error(request, "Error: User not found.")
            return render(request, "files/display.html", {"values": []})

        # ✅ Ensure CompanyData exists for the manager
        try:
            med = CompanyData.objects.get(manager=user)
        except CompanyData.DoesNotExist:
            messages.error(request, "No records found for this manager.")
            return render(request, "files/display.html", {"values": []})

        # ✅ Retrieve DataRecords associated with this company
        comp = DataRecord.objects.filter(key=med)

        # ✅ Debugging: Print DataRecords
        print("DEBUG - Retrieved DataRecords:", comp)

        if not comp.exists():
            messages.error(request, "No records found in the database.")
            return render(request, "files/display.html", {"values": []})

        values = []
        ctr = 1

        for item in comp:
            try:
                record_name = bytes.fromhex(item.record_name)
                name = AESCipher.decrypt(aes, record_name)
                quantity = paillier.decrypt(priv1, priv2, pub, int(item.record_content))
                cost = paillier.decrypt(priv1, priv2, pub, int(item.date_added))

                values.append(
                    {
                        "ctr": ctr,
                        "name": name,
                        "quantity": quantity,
                        "cost": cost,
                    }
                )
                ctr += 1
            except Exception as e:
                logger.error(f"Error processing DataRecord {item.id}: {e}")

        return render(
            request,
            "files/display.html",
            {"values": values, "med_name": med.company_name},
        )

    except Exception as e:
        logger.error(f"Unexpected error in display function: {e}")
        messages.error(request, "An unexpected error occurred.")
        return render(
            request,
            "files/display.html",
            {"values": values, "med_name": med.company_name},
        )


def CompanyDataName(request):
    return render(request, "files/CompanyDataName.html")


login_required(login_url="files:empLog")


def addDataRecord(request, employee_id):
    employee = get_object_or_404(Employee, id=employee_id)
    companyData = employee.company

    file_path = "employee.txt"
    if not os.path.exists(file_path):
        return render(
            request,
            "files/employee.html",
            {"employee": employee, "error": "Key file missing"},
        )

    with open(file_path, "r") as file:
        all_lines = file.readlines()

    if len(all_lines) < 2:
        return render(
            request,
            "files/employee.html",
            {"employee": employee, "error": "Invalid key file format"},
        )

    # ✅ Ensure pub_key is an integer
    try:
        pub_key = int(all_lines[0].strip())
    except ValueError:
        return render(
            request,
            "files/employee.html",
            {"employee": employee, "error": "Invalid public key format"},
        )

    aes_key = bytes.fromhex(all_lines[1].strip())

    # ✅ Ensure company_name is decrypted properly
    med_name = companyData.company_name
    if isinstance(med_name, str):
        try:
            med_name = bytes.fromhex(med_name)
            med_name = AESCipher.decrypt(aes_key, med_name)
        except Exception as e:
            return render(
                request,
                "files/employee.html",
                {"employee": employee, "error": f"Decryption error: {e}"},
            )

    if request.method == "POST":
        employee_name = employee.name
        date_field = datetime.now()
        name = request.POST.get("inputName", "").strip()
        quantity = request.POST.get("inputQuantity", "0").strip()
        cost = request.POST.get("inputCost", "0").strip()

        # ✅ Ensure proper type conversions
        try:
            quantity = int(quantity)
            cost = int(float(cost))  # Convert cost to float first, then integer
        except ValueError:
            return render(
                request,
                "files/employee.html",
                {"employee": employee, "error": "Invalid quantity or cost value"},
            )

        # ✅ Encrypt name using AES
        new_name = AESCipher.encrypt(name, aes_key).hex()
        new_quantity = paillier.encrypt(pub_key, quantity)  # Ensure `quantity` is int
        new_cost = paillier.encrypt(pub_key, cost)  # Ensure `cost` is int

        # ✅ Get or Create Data Record
        data_record, created = DataRecord.objects.get_or_create(
            record_name=new_name,
            key=companyData,  # ✅ Correct key association
            defaults={
                "record_content": str(new_quantity),
                "date_added": timezone.now(),
            },  # ✅ Ensure correct fields
        )

        if not created:
            existing_quantity = int(
                data_record.record_content
            )  # ✅ Convert encrypted value back to int
            updated_quantity = paillier.e_add(pub_key, existing_quantity, new_quantity)
            data_record.record_content = str(updated_quantity)  # ✅ Store as string
            data_record.save()

        # ✅ Fix: Create `Log` entry with correct fields
        log_entry = Log.objects.create(
            employee=employee,
            timestamp=date_field,
            data_record=data_record,  # ✅ Linking DataRecord correctly
            quantity=quantity,
            cost=cost,
        )
        log_entry.save()

        return HttpResponseRedirect(reverse("files:addDataRecord", args=[employee.id]))

    return render(
        request, "files/employee.html", {"employee": employee, "med_name": med_name}
    )


@login_required(login_url="/managerLogin/")
def managerDashboard(request):
    manager = request.user

    # ✅ Fetch all employees under this manager
    employees = Employee.objects.filter(manager=manager)

    # ✅ Fetch activity logs for these employees
    logs = Log.objects.filter(employee__in=employees).order_by("-timestamp")

    return render(
        request, "files/managerDashboard.html", {"logs": logs, "employees": employees}
    )


# def register(request):
#     CompanyData_name = "Crocin"
#     file = open('manager.txt')
#     all_lines = file.readlines()
#     key = all_lines[3]
#     key = key[2:-1]
#     key = key.encode('UTF-8')
#     encrypt_msg = AESCipher.encrypt(CompanyData_name, key)

#     return HttpResponse("<h1>Holla modamustfakaa</h1>")

# def register_med(request):

#     if request.method =='POST':
#         CompanyData = CompanyData(request.POST)
#         if CompanyData.is_valid():
#             CompanyData1 = CompanyData.save(commit=False)
#             priv,pub = paillier.generate_keypair(256)
#             a = priv.get_list()
#             priv1=a[0]
#             priv2 = a[1]
#             CompanyData1.privateKey_1 = priv1
#             CompanyData1.privateKey_2 = priv2
#             CompanyData1.publicKey = pub
#             CompanyData1.save()

#             return redirect('/home/')
#     else:
#         CompanyData = CompanyData()
#     return render(request,'files/test.html',{'CompanyData':CompanyData})

# def add_DataRecord(request,med_id):
#     medic = Key.objects.get(id = med_id)
#     if request.method == 'POST':
#         constituent = Constituent(request.POST)
#         if constituent.is_valid():
#             constituent1 = constituent.save(commit=False)
#             quant = int(constituent1.DataRecord_quantity)
#             cost = int(constituent1.DataRecord_cost)
#             pub = int(medic.publicKey)
#             new_cost= paillier.encrypt(int(pub),cost)
#             new_quant = paillier.encrypt(pub,quant)
#             constituent1.DataRecord_quantity = new_quant
#             constituent1.DataRecord_cost = new_cost
#             constituent1.key = medic
#             constituent1.save()
#             return redirect('/home/')
#     else:
#         constituent = Constituent()
#     return render(request,'files/constituent.html',{'constituent':constituent,'medic':medic})

# def home(request):
#     items = Key.objects.all()

#     return render(request,'files/home.html',{'items':items})

# def retrieve_DataRecords(request,id):
#     medic = Key.objects.get(id = id)
#     compo = DataRecord.objects.filter(key=medic)
#     a = {}
#     for c in compo:
#         c.DataRecord_cost = paillier.decrypt(int(medic.privateKey_1),int(medic.privateKey_2),int(medic.publicKey),int(c.DataRecord_cost))
#         c.DataRecord_quantity = paillier.decrypt(int(medic.privateKey_1), int(medic.privateKey_2), int(medic.publicKey),
#                                             int(c.DataRecord_quantity))
#         a[c.DataRecord_name] = [c.DataRecord_cost,c.DataRecord_quantity]

#     return render(request,'files/detail.html',{'a':a,'compo':compo})
