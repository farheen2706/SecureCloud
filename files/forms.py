from django import forms
from .models import Employee
from django.contrib.auth.models import User
from django import forms
from .models import CompanyData, DataRecord

# class Medicine(forms.ModelForm):
#     class Meta:
#         model = Key
#         fields = ('medicine_name',)


# class Constituent(forms.ModelForm):
#     class Meta:
#         model = Component
#         fields = ('component_name','component_cost','component_quantity',)	

class ManagerForm(forms.ModelForm):
	password = forms.CharField(widget=forms.PasswordInput)
	class Meta:
		model = User
		fields = ('username', 'password',)
		help_texts = {'username': None, 'password': None}

class CompanyDataForm(forms.ModelForm):  # Previously MedicineForm
    class Meta:
        model = CompanyData
        fields = ["company_name", "data_type", "encrypted_data"]

class DataRecordForm(forms.ModelForm):  # Previously ComponentForm
    class Meta:
        model = DataRecord
        fields = ["record_name", "record_content"]