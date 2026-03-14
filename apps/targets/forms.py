from django import forms

class TargetImportForm(forms.Form):
    csv_file = forms.FileField(
        label='Select a CSV file',
        help_text='Supported format: name, url, ip_address, description, protocol, is_active, tags'
    )
    handle_duplicates = forms.ChoiceField(
        choices=[
            ('skip', 'Skip duplicates'),
            ('update', 'Update existing targets'),
        ],
        initial='skip',
        widget=forms.RadioSelect
    )
