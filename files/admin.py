from django.contrib import admin
from .models import Employee, CompanyData, DataRecord, Log  # Updated model names
# Register your models here.

admin.site.register(Employee)
admin.site.register(CompanyData)  # Replaces Medicine
admin.site.register(DataRecord)  # Replaces Component
admin.site.register(Log)