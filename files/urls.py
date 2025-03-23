from django.contrib import admin
from django.urls import path,include
from . import views
from files.views import addDataRecord# ✅ Ensure this import is correct
from files.views import CompanyData
from .views import forgot_password, reset_password, change_password

app_name = 'files'

urlpatterns = [
    path("", views.home, name="home"),  # ✅ Add this for the homepage
    path("managerRegister/", views.managerRegister, name="manReg"),
    path("managerLogin/", views.managerLogin, name="manLog"),
    path("employeeLogin/", views.employeeLogin, name="empLog"),
    path("newPassword/", views.newPassword, name="newPass"),
    path("addEmployee/", views.addEmployee, name="addEmployee"),
    path("logs/", views.logs, name="logs"),
    path("display/", views.display, name="display"),
    path("companyData/", views.logout_view, name="logout"),
    path("employee/<int:employee_id>/", views.addDataRecord, name="addDataRecord"),
    path("managerDashboard/", views.managerDashboard, name="managerDashboard"),
    path('forgot-password/', forgot_password, name='forgot_password'),
    path('reset-password/<uidb64>/<token>/', reset_password, name='reset_password'),
    path('change-password/', change_password, name='change_password'),



    # path('<int:med_id>/',views.add_component,name='constituent'),
    # path('list/',views.home,name='home'),
    # path('list/<int:id>/',views.retrieve_components,name='retrieve'),
]
