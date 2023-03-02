from django.db import models
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser, PermissionsMixin
)
from django.db.models.signals import post_save
from django.dispatch import receiver
from uuid import uuid4
from datetime import datetime, timedelta
from django.contrib.auth.models import UserManager
from django.core.mail import EmailMessage
from django.template.loader import render_to_string


class UserManager(BaseUserManager):

    def create_user(self, username, email, password=None):
        if not email:
            raise ValueError('メールアドレスを入力してください')
        user = self.model(
            username=username,
            email=email,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None):
        user = self.model(
            username=username,
            email=email,
        )
        user.set_password(password)
        user.is_staff = True
        user.is_active = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255)
    email = models.EmailField(max_length=255, unique=True)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    thumbnail = models.FileField(null=True, upload_to='picture/')

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username',]

    objects = UserManager()

    class Meta:
        db_table = 'user'

    def __str__(self):
        return self.email


class UserActivateTokensManager(models.Manager):

    def activate_user_by_token(self, token):
        user_activate_token = self.filter(
            token=token,
            expired_at__gte=datetime.now()
        ).first()
        user = user_activate_token.user
        user.is_active = True
        user.save()


class UserActivateToken(models.Model):
    token = models.UUIDField(db_index=True)
    expired_at = models.DateTimeField()
    user = models.ForeignKey(
        'User', on_delete=models.CASCADE
    )

    objects = UserActivateTokensManager()

    class Meta:
        db_table = 'user_activate_token'


@receiver(post_save, sender=User)
def publish_token(sender, instance, **kwargs):
    user_activate_token = UserActivateToken.objects.create(
        user=instance,
        token=str(uuid4()),
        expired_at=datetime.now() + timedelta(days=1),
    )

    subject = 'Thanks regist new account'
    body = render_to_string(
        'accounts/mail_text/regist.txt', context={
            'username': User.username,
            'user_activate_token': user_activate_token.token
        }
    )

    from_email = ['admin@test.com']
    to = [User.email]

    email = EmailMessage(
        subject,
        body,
        from_email,
        to,
    )
    email.send()
