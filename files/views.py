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

from django.http import HttpResponseRedirect
from django.urls import reverse
# 🔹 Import Paillier Encryption & AES Cipher for Secure Data Handling
from . import paillier, AESCipher

# 🔹 Import Models (Updated for Company Data Storage)
from files.models import Employee, DataRecord, Log  # ✅ Correct Import


# 🔹 Import Forms (Updated for Company Data Storage)
from .forms import ManagerForm, CompanyDataForm, DataRecordForm

# 🔹 Import Email Configuration
from server.email_info import EMAIL_HOST_USER
from supabase import create_client, Client
from django.conf import settings

supabase: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)

def home(request):
    return render(request, "files/home.html")  # Renders home.html


def logs(request):
    """Fetch logs for employees under the logged-in manager from Supabase."""

    manager_id = request.user.id

    # ✅ Fetch employees managed by the logged-in manager
    employee_response = supabase.table("employees").select("id").eq("manager_id", manager_id).execute()

    if not employee_response.data:
        messages.error(request, "No employees found under this manager.")
        return render(request, "files/logs.html", {"logs": []})

    employee_ids = [emp["id"] for emp in employee_response.data]

    # ✅ Fetch logs associated with those employees
    logs_response = supabase.table("logs").select("*").in_("employee_id", employee_ids).order("timestamp", desc=True).execute()

    if not logs_response.data:
        messages.warning(request, "No log entries found.")
        return render(request, "files/logs.html", {"logs": []})

    return render(request, "files/logs.html", {"logs": logs_response.data})



def logout_view(request):
    """Logs out the user and redirects to the home page."""
    logout(request)
    return redirect("home")


# Set up logging for email errors
logger = logging.getLogger(__name__)


def employeeLogin(request):
    """Authenticate employee using Supabase."""
    
    if request.method == "POST":
        emp_email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "").strip()

        # ✅ Fetch employee from Supabase
        response = supabase.table("employees").select("*").eq("email", emp_email).execute()
        
        if not response.data:  # ❌ Employee not found
            messages.error(request, "Employee not found.")
            print(f"❌ Employee not found: {emp_email}")
            return render(request, "files/employeeLogin.html")

        employee_data = response.data[0]  # Get first employee record
        stored_password = employee_data["password"]  # Hashed password

        # ✅ Validate Password
        if not check_password(password, stored_password):
            messages.error(request, "Incorrect password.")
            print(f"❌ Incorrect password for {emp_email}")
            return render(request, "files/employeeLogin.html")

        # ✅ Login Successful
        print(f"✅ Employee {emp_email} logged in successfully!")
        request.session["employee_id"] = employee_data["id"]  # Store session

        return redirect(f"/employee/{employee_data['id']}/")  # ✅ Redirect to Employee Page

    return render(request, "files/employeeLogin.html")


def newPassword(request):
    return render(request, "files/newPassword.html")


def managerLogin(request):
    if request.method == "POST":
        print("POST Data:", request.POST)  # Debugging

        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "").strip()

        if not username or not password:
            messages.error(request, "Please enter both username and password.")
            return render(request, "files/managerLogin.html")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            print(f"✅ Login successful: {user.username}")  # Debugging
            return redirect("managerDashboard")  # Redirect after login
        else:
            print("❌ Authentication failed")  # Debugging
            messages.error(request, "Invalid username or password.")
            return render(request, "files/managerLogin.html")

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
@csrf_protect
def managerRegister(request):
    if request.method == "POST":
        user_form = ManagerForm(request.POST)
        company_name = request.POST.get("company_name", "").strip()  # ✅ Ensure correct field name

        if user_form.is_valid():
            user = user_form.save(commit=False)
            username = user_form.cleaned_data.get("username", "defaultuser")
            password = user_form.cleaned_data.get("password", "defaultpassword123")
            user.set_password(password)
            user.save()

            try:
                key_size = 256
                priv, pub_obj = paillier.generate_keypair(key_size)
                pub = int(pub_obj.n)
                priv1, priv2 = priv.get_list()
                aes_key = AESCipher.gen_key()

                # ✅ Encrypt company name
                encrypted_company_name = AESCipher.encrypt(company_name, aes_key).hex()

                # ✅ Ensure company data is correctly stored
                company_instance, created = CompanyData.objects.update_or_create(
                    manager=user, defaults={"company_name": encrypted_company_name}
                )

                # ✅ Store keys securely
                with open("manager.txt", "w") as f:
                    f.write(f"{pub}\n{priv1}\n{priv2}\n{aes_key.hex()}")

                with open("employee.txt", "w") as f:
                    f.write(f"{pub}\n{aes_key.hex()}")

                # ✅ Authenticate and redirect
                user = authenticate(username=username, password=password)
                if user:
                    login(request, user)
                    return redirect(reverse("files:addEmployee"))
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
    company_instance = CompanyData.objects.filter(manager=manager_user).first()
    if not company_instance:
        messages.error(request, "No company assigned. Register company data first.")
        return redirect("files:managerDashboard")

    company_id = company_instance.id
    print(f"🔍 DEBUG: company_id = {company_id}, Type: {type(company_id)}")  # ✅ Ensure company_id exists

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
            data = {
                "email": emp_email,
                "name": emp_name,
                "company_id": company_id,  # ✅ Use company_id directly
                "password": hashed_password,  # ✅ Store hashed password
                "manager_id": request.user.id
            }

            response = supabase.table("employees").insert(data).execute()
            
            print("🔍 Supabase Full Response:", response)  # ✅ Debugging

            # ✅ Correct error handling
            if response is None or not hasattr(response, "data") or not response.data:
                messages.error(request, "Failed to add employee: No data returned.")
                print("❌ Supabase Error: Response is None or data is empty.")
            elif hasattr(response, "error"):
                messages.error(request, f"Failed to add employee: {response.error['message']}")
                print(f"❌ Supabase Error: {response.error}")
            else:
                print(f"✅ Employee Created: {emp_email}")
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

    values = []  # ✅ Ensure 'values' is always initialized

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
        user = request.user  # Directly using request.user

        # ✅ Ensure CompanyData exists for the manager
        try:
            med = CompanyData.objects.get(manager=user)
        except CompanyData.DoesNotExist:
            messages.error(request, "No records found for this manager.")
            return render(request, "files/display.html", {"values": []})

        # ✅ Retrieve DataRecords associated with this company from Supabase
        response = supabase.table("data_records").select("*").eq("key", med.id).execute()
        comp = response.data if response.data else []

        # ✅ Debugging: Print DataRecords
        print("DEBUG - Retrieved DataRecords:", comp)

        if not comp:  # ✅ Fix: Correct way to check if list is empty
            messages.error(request, "No records found in the database.")
            return render(request, "files/display.html", {"values": []})

        ctr = 1
        for item in comp:
            try:
                record_name = bytes.fromhex(item["record_name"])  # ✅ Fix: Use dict key access
                name = AESCipher.decrypt(aes, record_name)
                quantity = paillier.decrypt(priv1, priv2, pub, int(item["record_content"]))
                cost = paillier.decrypt(priv1, priv2, pub, int(item["date_added"]))

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
                logger.error(f"Error processing DataRecord {item.get('id', 'unknown')}: {e}")

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
            {"values": values, "med_name": getattr(med, 'company_name', 'Unknown')},  # ✅ Prevent crash if 'med' is missing
        )
        
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

        # Ensure the manager exists
        user = request.user  # Django's built-in user authentication

        # Ensure CompanyData exists for the manager
        try:
            med = CompanyData.objects.get(manager=user)
            logger.debug(f"🔍 DEBUG: Found CompanyData -> ID: {med.id}, Name: {med.company_name}")
        except CompanyData.DoesNotExist:
            messages.error(request, "No records found for this manager.")
            return render(request, "files/display.html", {"values": []})

        # ✅ Retrieve DataRecords using the correct column name `key_id`
        response = supabase.table("data_records").select("*").eq("key_id", med.id).execute()

        # ✅ Ensure response contains data
        if not response.data:
            logger.debug("DEBUG - Retrieved 0 DataRecords: []")
            messages.error(request, "No records found in the database.")
            return render(request, "files/display.html", {"values": []})

        values = []
        ctr = 1

        for item in response.data:
            try:
                record_name = bytes.fromhex(item["record_name"])
                name = AESCipher.decrypt(aes, record_name)
                quantity = paillier.decrypt(priv1, priv2, pub, int(item["record_content"]))
                cost = paillier.decrypt(priv1, priv2, pub, int(item["date_added"]))

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
                logger.error(f"Error processing DataRecord {item['id']}: {e}")

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
            {"values": [], "med_name": med.company_name if 'med' in locals() else ''},
        )


def CompanyDataName(request):
    return render(request, "files/CompanyDataName.html")


login_required(login_url="files:empLog")


def addDataRecord(request, employee_id):
    """Fetch employee from Supabase and handle data record creation/updation."""
    
    # ✅ Fetch employee from Supabase instead of Django ORM
    response = supabase.table("employees").select("*").eq("id", employee_id).execute()
    if not response.data:
         return render(request, "files/error.html", {"error": "Employee not found."})


    employee = response.data[0]  # ✅ Employee found
    company_id = employee["company_id"]

    # ✅ Fetch Company Data from Supabase
    company_response = supabase.table("files_companydata").select("*").eq("id", company_id).execute()
    if not company_response.data:
        return render(request, "files/error.html", {"error": "Company data not found."})

    company_data = company_response.data[0]

    file_path = "employee.txt"
    if not os.path.exists(file_path):
        return render(request, "files/employee.html", {"employee": employee, "error": "Key file missing"})

    with open(file_path, "r") as file:
        all_lines = file.readlines()

    if len(all_lines) < 2:
        return render(request, "files/employee.html", {"employee": employee, "error": "Invalid key file format"})

    # ✅ Ensure pub_key is an integer
    try:
        pub_key = int(all_lines[0].strip())
    except ValueError:
        return render(request, "files/employee.html", {"employee": employee, "error": "Invalid public key format"})

    aes_key = bytes.fromhex(all_lines[1].strip())

    # ✅ Ensure company_name is decrypted properly
    med_name = company_data["company_name"]
    if isinstance(med_name, str):
        try:
            med_name = bytes.fromhex(med_name)
            med_name = AESCipher.decrypt(aes_key, med_name)
        except Exception as e:
            return render(request, "files/employee.html", {"employee": employee, "error": f"Decryption error: {e}"})

    if request.method == "POST":
        date_field = datetime.now()
        name = request.POST.get("inputName", "").strip()
        quantity = request.POST.get("inputQuantity", "0").strip()
        cost = request.POST.get("inputCost", "0").strip()

        # ✅ Ensure proper type conversions
        try:
            quantity = int(quantity)
            cost = int(float(cost))  # Convert cost to float first, then integer
        except ValueError:
            return render(request, "files/employee.html", {"employee": employee, "error": "Invalid quantity or cost value"})

        # ✅ Encrypt name using AES
        new_name = AESCipher.encrypt(name, aes_key).hex()
        new_quantity = paillier.encrypt(pub_key, quantity)
        new_cost = paillier.encrypt(pub_key, cost)

        # ✅ Check if DataRecord exists in Supabase
        response = supabase.table("data_records").select("*").eq("record_name", new_name).execute()

        if not response.data:
            messages.error(request, f"Failed to fetch data records: {response.error}")
            return render(request, "files/employee.html", {"employee": employee, "med_name": med_name})

        existing_records = response.data

        if existing_records:
            # ✅ Update existing record in Supabase
            existing_record = existing_records[0]
            existing_quantity = int(existing_record["record_content"])
            updated_quantity = paillier.e_add(pub_key, existing_quantity, new_quantity)

            update_response = supabase.table("data_records").update(
                {"record_content": str(updated_quantity)}
            ).eq("record_name", new_name).execute()

            if update_response.error:
                messages.error(request, f"Failed to update data record: {update_response.error}")
                return render(request, "files/employee.html", {"employee": employee, "med_name": med_name})

        else:
            # ✅ Insert new DataRecord into Supabase
            data = {
                "key_id": company_data["id"],
                "record_name": new_name,
                "record_content": str(new_quantity),
                "date_added": str(date_field),
            }
            insert_response = supabase.table("data_records").insert(data).execute()

            if insert_response.error:
                messages.error(request, f"Failed to add data record: {insert_response.error}")
                return render(request, "files/employee.html", {"employee": employee, "med_name": med_name})

        # ✅ Insert Log Entry into Supabase
        log_data = {
            "employee_id": employee["id"],
            "timestamp": str(date_field),
            "data_record_name": new_name,
            "quantity": quantity,
            "cost": cost
        }
        log_response = supabase.table("logs").insert(log_data).execute()

        if log_response.error:
            messages.error(request, f"Failed to add log entry: {log_response.error}")
        else:
            messages.success(request, "Data record and log entry successfully saved!")

        return HttpResponseRedirect(reverse("files:addDataRecord", args=[employee["id"]]))

    return render(request, "files/employee.html", {"employee": employee, "med_name": med_name})


@login_required(login_url="/managerLogin/")
def managerDashboard(request):
    manager_id = request.user

    # ✅ Fetch all employees under this manager

    response = supabase.table("employees").select("*").eq("manager_id", request.user.id).execute()
    employees = response.data if response.data else []

    # ✅ Fetch activity logs for these employees
    response = supabase.table("logs").select("*").order("timestamp", desc=True).execute()
    logs = response.data if response.data else []

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
