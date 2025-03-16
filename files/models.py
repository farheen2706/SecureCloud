from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import AbstractBaseUser
from django.utils.timezone import now 



class CompanyData(models.Model):  # Previously Medicine
    manager = models.ForeignKey(User, on_delete=models.CASCADE)  
    company_name = models.CharField(max_length=255)  # ✅ Ensure this field exists
    data_type = models.CharField(max_length=255)
    encrypted_data = models.TextField()  # ✅ Storing encrypted company data

    def __str__(self):
       return self.company_name


class DataRecord(models.Model):
    key = models.ForeignKey(CompanyData, on_delete=models.CASCADE)  
    record_name = models.CharField(max_length=255)  
    record_content = models.TextField()  
    date_added = models.DateTimeField(auto_now_add=True)  
    quantity = models.IntegerField(default=0)  # ✅ Add this field
    cost = models.FloatField(default=0.0) 
    
class Employee(models.Model):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255)
    manager = models.ForeignKey(User, on_delete=models.CASCADE)  # Link to manager/admin
    company = models.ForeignKey(CompanyData, on_delete=models.CASCADE)  # Link to company
    role = models.CharField(max_length=100, choices=[('admin', 'Admin'), ('user', 'User')])  # Role-based access
    password = models.CharField(max_length=255)  # Store hashed password
    last_login = models.DateTimeField(default=now)

class FileStorage(models.Model):
    company = models.ForeignKey(CompanyData, on_delete=models.CASCADE)  # Link to a company
    file_name = models.CharField(max_length=255)  # Name of the stored file
    encrypted_file = models.TextField()  # Store encrypted file data
    uploaded_at = models.DateTimeField(auto_now_add=True)  # Timestamp

class Log(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE)  # ✅ ForeignKey to Employee
    data_record = models.ForeignKey(DataRecord, on_delete=models.CASCADE, null=True, blank=True)
    quantity = models.IntegerField()
    cost = models.FloatField()
    
    def __str__(self):
        return f"Log {self.id} - {self.employee.name}"




# class Key(models.Model):
#     medicine_name = models.CharField(max_length=100,default=None)
#     privateKey_1 = models.CharField(max_length=500,default=None)
#     privateKey_2 = models.CharField(max_length=500,default=None)
#     publicKey = models.CharField(max_length=500,default=None)

#     def __str__(self):
#         return self.medicine_name