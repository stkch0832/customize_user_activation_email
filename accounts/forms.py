from django import forms
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password

User = get_user_model()


class RegistForm(forms.ModelForm):
    # username = forms.CharField(label='名前')
    # email = forms.EmailField(label='メールアドレス')
    # password = forms.CharField(label='password', widget=forms.PasswordInput)

    confirm_password = forms.CharField(
        label='',
        widget=forms.PasswordInput(
            attrs={
                'class': 'form-control',
                'placeholder': 'パスワード（確認用）',
            })
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        labels = {
            'username': '',
            'email': '',
            'password': '',
        }
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'ユーザー名',
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'メールアドレス',
            }),
            'password': forms.PasswordInput(attrs={
                'class': 'form-control',
                'placeholder': 'パスワード',
            }),
        }

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data['password']
        confirm_password = cleaned_data['confirm_password']
        if password != confirm_password:
            raise ValidationError('パスワードが一致しません')

    def save(self, commit=False):
        user = super().save(commit=False)
        validate_password(self.cleaned_data['password'])
        user.set_password(self.cleaned_data['password'])
        user.save()
        return user


class LoginForm(forms.Form):
    email = forms.EmailField(
        required=True,
        label='',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'メールアドレス',
        })
    )
    password = forms.CharField(
        required=True,
        label='',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'パスワード',
        })
    )

# class LoginForm(forms.ModelForm):

#     class Meta:
#         model = User
#         fields = ('email', 'password')
#         labels = {
#             'email': '',
#             'password': '',
#         }
#         widgets = {
#             'email': forms.EmailInput(attrs={
#                 'class': 'form-control',
#                 'placeholder': 'メールアドレス'
#             }),

#             'password': forms.PasswordInput(attrs={
#                 'class': 'form-control',
#                 'placeholder': 'パスワード'
#             }),
#         }
