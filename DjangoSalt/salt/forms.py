from django import forms



class UserForm(forms.Form):
    saltClient = forms.CharField(label="client", max_length=50)
    saltParams1 = forms.CharField(label="params1", max_length=100)
    saltParams2 = forms.CharField(label="params2", max_length=100)
class SaltForm(forms.Form):
    Client = forms.CharField(label="client", max_length=50)
    Params = forms.CharField(label="params", max_length=100)

class DownloadForm(forms.Form):
    projectname = forms.CharField(label="projectname", max_length=50)
    filename = forms.CharField(label="filename", max_length=100)

class LogNameForm(forms.Form):
    loglist = forms.CharField(label="loglist", max_length=100)

class SQLListForm(forms.Form):
    sqllist = forms.CharField(label="sqlname", max_length=100)

class SQLNameForm(forms.Form):
    sqlname = forms.CharField(label="sqlname", max_length=100)
