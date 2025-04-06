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
import traceback  # Add this import at the top if not already
import json
from django.http import JsonResponse
from django.utils import timezone
import re
from dateutil.parser import parse as parse_date
from django.utils.dateparse import parse_datetime

supabase: Client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)

def home(request):
    return render(request, "files/home.html")  # Renders home.html


from dateutil.parser import parse as parse_date

def logs(request):
    """Fetch and decrypt employee logs under current manager."""
    
    def is_valid_hex(s):
        if not isinstance(s, str) or len(s) % 2 != 0:
            return False
        try:
            bytes.fromhex(s)
            return True
        except ValueError:
            return False

    try:
        pub = int(os.environ["PAILLIER_PUB"])
        priv1 = int(os.environ["PAILLIER_PRIV1"])
        priv2 = int(os.environ["PAILLIER_PRIV2"])
        aes_key = bytes.fromhex(os.environ["AES_KEY"])
    except Exception as e:
        messages.error(request, f"Encryption environment variables missing/invalid: {e}")
        return render(request, "files/logs.html", {"logs": []})

    # Fetch employees under manager
    emp_resp = supabase.table("files_employee")\
        .select("id")\
        .eq("manager_id", request.user.id)\
        .execute()
    
    if not emp_resp.data:
        messages.info(request, "No employees found.")
        return render(request, "files/logs.html", {"logs": []})

    emp_ids = [e["id"] for e in emp_resp.data]

    # Fetch logs
    logs_resp = supabase.table("files_log")\
        .select("*, data_record:files_datarecord(record_name), employee:files_employee(name)")\
        .in_("employee_id", emp_ids)\
        .order("timestamp", desc=True)\
        .execute()

    decrypted_logs = []

    for entry in logs_resp.data:
        try:
            print("\n🔍 Processing Log Entry")

            emp = entry.get("employee", {})
            data_rec = entry.get("data_record", {})

            # 🔐 AES Decrypt record name
            enc_name = data_rec.get("record_name", "")
            if is_valid_hex(enc_name):
                decrypted_name = AESCipher.decrypt(aes_key, bytes.fromhex(enc_name))
            else:
                decrypted_name = "❌ Invalid AES"

            # 🔐 Paillier Decrypt quantity
            qty_enc = entry.get("quantity")
            try:
                qty_dec = paillier.decrypt(priv1, priv2, pub, int(qty_enc)) if qty_enc else "N/A"
            except Exception:
                qty_dec = "❌ Error"

            # 🔐 Paillier Decrypt cost
            cost_enc = entry.get("cost")
            try:
                cost_dec = paillier.decrypt(priv1, priv2, pub, int(cost_enc)) if cost_enc else "N/A"
            except Exception:
                cost_dec = "❌ Error"

            # 🕒 Format timestamp
            ts = entry.get("timestamp")
            ts_fmt = parse_datetime(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "N/A"

            log_obj = {
                "timestamp": ts_fmt,
                "employee_name": emp.get("name", "Unknown"),
                "record_name": decrypted_name,
                "record_name_enc": enc_name,
                "quantity_enc": qty_enc,
                "quantity_dec": qty_dec,
                "cost_enc": cost_enc,
                "cost_dec": cost_dec
            }

            print("✅ Decrypted Log:", log_obj)
            decrypted_logs.append(log_obj)

        except Exception as e:
            print("⚠️ Log entry error:", e)

    return render(request, "files/logs.html", {"logs": decrypted_logs})


def logout_view(request):
    """Logs out the user and redirects to the home page."""
    logout(request)
    return redirect("home")


# Set up logging for email errors
logger = logging.getLogger(__name__)


from django.urls import reverse

def employeeLogin(request):
    """Authenticate employee using Supabase and maintain a session marker."""

    if request.method == "POST":
        emp_email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "").strip()

        try:
            response = supabase.table("files_employee").select("*").eq("email", emp_email).execute()
        except Exception as e:
            messages.error(request, "Error connecting to database.")
            return render(request, "files/employeeLogin.html")

        if not response.data:
            messages.error(request, "Employee not found.")
            return render(request, "files/employeeLogin.html")

        employee_data = response.data[0]
        stored_password = employee_data.get("password")

        if not stored_password or not check_password(password, stored_password):
            messages.error(request, "Incorrect password.")
            return render(request, "files/employeeLogin.html")

        # Flush old session and start a new one
        request.session.flush()
        request.session["employee_id"] = employee_data["id"]
        request.session["user_type"] = "employee"
        request.session.modified = True

        return redirect(f"/employee/{employee_data['id']}/")

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
            return redirect("files:managerDashboard")  # Redirect after login
        else:
            print("❌ Authentication failed")  # Debugging
            messages.error(request, "Invalid username or password.")
            return render(request, "files/managerLogin.html")

    return render(request, "files/managerLogin.html")

def managerDashboard(request):
    manager_id = request.user

    # ✅ Fetch all employees under this manager

    response = supabase.table("files_employee").select("*").eq("manager_id", request.user.id).execute()
    employees = response.data if response.data else []

    # ✅ Fetch activity logs for these employees
    response = supabase.table("files_log").select("*").order("timestamp", desc=True).execute()
    logs = response.data if response.data else []

    return render(
        request, "files/managerDashboard.html", {"logs": logs, "employees": employees}
    )
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
    
    if not request.user.is_authenticated:
        messages.error(request, "You must be logged in to add employees.")
        return redirect("files:manLog")

    manager_user = request.user
    company_instance = CompanyData.objects.filter(manager=manager_user).first()
    
    if not company_instance:
        messages.error(request, "No company assigned. Register company data first.")
        return redirect("files:managerDashboard")

    company_id = company_instance.id  # Ensure bigint compatibility
    manager_id = manager_user.id  # Ensure integer compatibility
    
    print(f"🔐 Authenticated Manager: {manager_user.username} (ID: {manager_id})")
    print(f"🏢 Associated Company ID: {company_id} (Type: {type(company_id)})")

    # Validate URL resolution
    try:
        available_urls = [
            name for name in get_resolver().reverse_dict.keys() if isinstance(name, str)
        ]
        print(f"🔗 Available URL Names: {available_urls}")
        resolved_url = reverse("files:addEmployee")
        print(f"📎 Resolved URL for addEmployee: {resolved_url}")
    except Resolver404 as e:
        logger.error(f"⚠️ Reverse resolution failed: {e}")
        messages.error(request, "Internal error: URL resolution failed.")
        return redirect("files:managerDashboard")

    if request.method == "POST":
        print("📨 POST request received at /addEmployee/")
        
        emp_name = request.POST.get("inputName", "").strip()
        emp_email = request.POST.get("inputEmail3", "").strip()

        if not emp_name or not emp_email:
            messages.error(request, "Employee name and email are required.")
            return render(request, "files/addEmployee.html")

        if Employee.objects.filter(email=emp_email).exists():
            messages.error(request, "An employee with this email already exists.")
            return render(request, "files/addEmployee.html")

        # Generate and hash password
        random_password = "".join(random.choices(string.ascii_letters + string.digits, k=10))
        hashed_password = make_password(random_password)

        data = {
            "email": emp_email,
            "name": emp_name,
            "role": "employee",  # Ensuring role is explicitly defined
            "company_id": company_id,  # bigint (int8)
            "password": hashed_password,
            "manager_id": manager_id  # integer (int4)
        }

        print(f"📦 Inserting Data into Supabase: {data}")

        try:
            response = supabase.table("files_employee").insert(data).execute()
            print(f"🧾 Supabase Response: {repr(response)}")
            
            # Validate Supabase Response
            if response is None or not getattr(response, "data", None):
                messages.error(request, "Failed to add employee: No response or empty data.")
                return render(request, "files/addEmployee.html")

            if hasattr(response, "error") and response.error:
                error_msg = response.error.get("message", "Unknown error")
                messages.error(request, f"Failed to add employee: {error_msg}")
                return render(request, "files/addEmployee.html")

            # Success: Send email with credentials
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
                messages.success(request, f"Employee '{emp_name}' added successfully. Login details sent to {emp_email}.")
            except Exception as email_error:
                logger.error(f"❌ Email sending failed for {emp_email}. Error: {email_error}")
                messages.warning(request, "Employee added, but email could not be sent.")

        except Exception as e:
            logger.error(f"❌ Supabase insertion failed: {repr(e)}", exc_info=True)
            messages.error(request, f"Failed to add employee. Error: {str(e)}")
            return render(request, "files/addEmployee.html")

        return HttpResponseRedirect(reverse("files:addEmployee"))

    return render(request, "files/addEmployee.html")


login_required(login_url="files:manLog")

def is_hex(s):
    return isinstance(s, str) and re.fullmatch(r"[0-9a-fA-F]+", s) is not None

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

        user = request.user

        try:
            med = CompanyData.objects.get(manager=user)
            logger.debug(f"🔍 DEBUG: Found CompanyData -> ID: {med.id}, Name: {med.company_name}")
        except CompanyData.DoesNotExist:
            messages.error(request, "No records found for this manager.")
            return render(request, "files/display.html", {"values": []})

        response = supabase.table("files_datarecord").select("*").eq("key_id", med.id).execute()

        if not response.data:
            logger.debug("DEBUG - Retrieved 0 DataRecords: []")
            messages.error(request, "No records found in the database.")
            return render(request, "files/display.html", {"values": []})

        values = []
        ctr = 1

        for item in response.data:
            try:
                # Safely decode hex and decrypt
                record_name_hex = item.get("record_name", "")
                record_content_raw = item.get("record_content", "")
                date_added_raw = item.get("date_added", "")

                if not is_hex(record_name_hex):
                    raise ValueError("record_name is not valid hex")

                record_name = bytes.fromhex(record_name_hex)
                name = AESCipher.decrypt(aes, record_name)

                quantity = int(record_content_raw)
                cost = int(date_added_raw)

                quantity = paillier.decrypt(priv1, priv2, pub, quantity)
                cost = paillier.decrypt(priv1, priv2, pub, cost)

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
                logger.warning(f"⚠️ Skipping malformed DataRecord ID {item.get('id', 'unknown')}: {e}")

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



def addDataRecord(request, employee_id):
    """Encrypt inputs with Paillier/AES, store in Supabase, and log the action."""

    # Only employees
    if request.session.get("user_type") != "employee":
        messages.error(request, "Access denied! Employees only.")
        return redirect("files:empLog")

    # Fetch employee & company
    employee = get_object_or_404(Employee, id=employee_id)
    company = employee.company

    # Load keys
    import os

    try:
        pub_key = int(os.environ.get("PUBLIC_KEY"))
        aes_key = bytes.fromhex(os.environ.get("AES_KEY"))
    except Exception as e:
        messages.error(request, f"Key load error: {e}")
        return render(request, "files/employee.html", {"employee": employee})

    if request.method == "GET":
        return render(request, "files/employee.html", {"employee": employee})

    # POST: process form
    name = request.POST.get("inputName", "").strip()
    qty_raw = request.POST.get("inputQuantity", "").strip()
    cost_raw = request.POST.get("inputCost", "").strip()

    if not all([name, qty_raw, cost_raw]):
        return JsonResponse({"error": "Missing fields"}, status=400)

    try:
        quantity = int(qty_raw)
        cost = float(cost_raw)
    except ValueError:
        return JsonResponse({"error": "Quantity and cost must be numeric"}, status=400)

    # --- LIVE ENCRYPTION LOGGING ---
    print(f"🔐 [AES] Encrypting record name: {name}")
    encrypted_name = AESCipher.encrypt(name, aes_key).hex()
    print(f"   → Encrypted name (hex): {encrypted_name}")

    print(f"🔢 [Paillier] Encrypting quantity: {quantity}")
    encrypted_qty = paillier.encrypt(pub_key, quantity)
    print(f"   → Encrypted quantity (int): {encrypted_qty}")

    print(f"💲 [Paillier] Encrypting cost: {cost}")
    encrypted_cost = paillier.encrypt(pub_key, int(cost))
    print(f"   → Encrypted cost (int): {encrypted_cost}")
    # --- END LIVE LOGGING ---

    timestamp = now().isoformat()

    try:
        # Check existing
        rec_check = supabase.table("files_datarecord")\
            .select("*").eq("record_name", encrypted_name).execute()
        existing = rec_check.data

        if existing:
            print(f"🔄 Found existing record ID {existing[0]['id']}, updating...")
            existing_qty = int(existing[0]["record_content"])
            new_qty = paillier.e_add(pub_key, existing_qty, encrypted_qty)
            print(f"   → Updated quantity ciphertext: {new_qty}")
            supabase.table("files_datarecord")\
                .update({
                    "record_content": str(new_qty),
                    "quantity": str(new_qty)
                })\
                .eq("record_name", encrypted_name).execute()
            data_record_id = existing[0]["id"]
        else:
            print("➕ Inserting new encrypted record...")
            resp = supabase.table("files_datarecord").insert({
                "key_id": company.id,
                "record_name": encrypted_name,
                "record_content": str(encrypted_qty),
                "date_added": timestamp,
                "quantity": str(encrypted_qty),  # encrypted string
                "cost": str(encrypted_cost)      # encrypted string
            }).execute()
            data_record_id = resp.data[0]["id"]
            print(f"   → Inserted record ID: {data_record_id}")

        # Log the operation including decrypted values
        print(f"📝 Logging operation for data_record_id={data_record_id}")
        supabase.table("files_log").insert({
            "employee_id":    employee.id,
            "data_record_id": data_record_id,
            "timestamp":      timestamp,
            "quantity":       str(encrypted_qty),     # encrypted
            "cost":           str(encrypted_cost),     # encrypted
            "quantity_dec":   str(quantity),           # decrypted quantity
            "cost_dec":       str(int(cost)),          # decrypted cost
            "action":         f"Encrypted record '{name}' stored"
        }).execute()

        return JsonResponse({"message": "Data record and log saved!"}, status=201)

    except Exception as e:
        print(f"❌ Error during encryption/storage: {e}")
        return JsonResponse({"error": str(e)}, status=500)

    
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
