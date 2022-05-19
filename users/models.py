from django.contrib.auth.models import PermissionsMixin
from django.db import models

from django.contrib.auth.base_user import BaseUserManager, AbstractBaseUser

from django.utils import timezone


class CustomUserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifiers
    for authentication instead of usernames.
    """

    def create_user(self, email, password, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        if not email:
            raise ValueError('The Email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self.create_user(email, password, **extra_fields)


BLOOD_GROUP_CHOICES = (
    ("aPositive", "A+"),
    ("aNegative", "A-"),
    ("bPositive", "B+"),
    ("bNegative", "B-"),
    ("abPositive", "AB+"),
    ("abNegative", "AB-"),
    ("oPositive", "O+"),
    ("o Negative", "O-"),
)

DISTRICTS_OF_NEPAL = (('achham', 'achham'),
                      ('arghakhanchi', 'arghakhanchi'),
                      ('baglung', 'baglung'),
                      ('baitadi', 'baitadi'),
                      ('bajhang', 'bajhang'),
                      ('bajura', 'bajura'),
                      ('banke', 'banke'),
                      ('bara', 'bara'),
                      ('bardiya', 'bardiya'),
                      ('bhaktapur', 'bhaktapur'),
                      ('bhojpur', 'bhojpur'),
                      ('chitwan', 'chitwan'),
                      ('dadeldhura', 'dadeldhura'),
                      ('dailekh', 'dailekh'),
                      ('dang deukhuri', 'dang deukhuri'),
                      ('darchula', 'darchula'),
                      ('dhading', 'dhading'),
                      ('dhankuta', 'dhankuta'),
                      ('dhanusa', 'dhanusa'),
                      ('dholkha', 'dholkha'),
                      ('dolpa', 'dolpa'),
                      ('doti', 'doti'),
                      ('gorkha', 'gorkha'),
                      ('gulmi', 'gulmi'),
                      ('humla', 'humla'),
                      ('ilam', 'ilam'),
                      ('jajarkot', 'jajarkot'),
                      ('jhapa', 'jhapa'),
                      ('jumla', 'jumla'),
                      ('kailali', 'kailali'),
                      ('kalikot', 'kalikot'),
                      ('kanchanpur', 'kanchanpur'),
                      ('kapilvastu', 'kapilvastu'),
                      ('kaski', 'kaski'),
                      ('kathmandu', 'kathmandu'),
                      ('kavrepalanchok', 'kavrepalanchok'),
                      ('khotang', 'khotang'),
                      ('lalitpur', 'lalitpur'),
                      ('lamjung', 'lamjung'),
                      ('mahottari', 'mahottari'),
                      ('makwanpur', 'makwanpur'),
                      ('manang', 'manang'),
                      ('morang', 'morang'),
                      ('mugu', 'mugu'),
                      ('mustang', 'mustang'),
                      ('myagdi', 'myagdi'),
                      ('nawalparasi', 'nawalparasi'),
                      ('nuwakot', 'nuwakot'),
                      ('okhaldhunga', 'okhaldhunga'),
                      ('palpa', 'palpa'),
                      ('panchthar', 'panchthar'),
                      ('parbat', 'parbat'),
                      ('parsa', 'parsa'),
                      ('pyuthan', 'pyuthan'),
                      ('ramechhap', 'ramechhap'),
                      ('rasuwa', 'rasuwa'),
                      ('rautahat', 'rautahat'),
                      ('rolpa', 'rolpa'),
                      ('rukum', 'rukum'),
                      ('rupandehi', 'rupandehi'),
                      ('salyan', 'salyan'),
                      ('sankhuwasabha', 'sankhuwasabha'),
                      ('saptari', 'saptari'),
                      ('sarlahi', 'sarlahi'),
                      ('sindhuli', 'sindhuli'),
                      ('sindhupalchok', 'sindhupalchok'),
                      ('siraha', 'siraha'),
                      ('solukhumbu', 'solukhumbu'),
                      ('sunsari', 'sunsari'),
                      ('surkhet', 'surkhet'),
                      ('syangja', 'syangja'),
                      ('tanahu', 'tanahu'),
                      ('taplejung', 'taplejung'),
                      ('terhathum', 'terhathum'),
                      ('udayapur', 'udayapur'))


class CustomUser(AbstractBaseUser, PermissionsMixin):
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)

    # Your custom user fields
    email = models.EmailField('email address', unique=True)
    username = models.CharField('username', unique=True, max_length=255)
    fullname = models.CharField('full name', max_length=400)
    address = models.CharField('address', choices=DISTRICTS_OF_NEPAL, max_length=400, default=None, null=True)
    contact = models.IntegerField('contact no', default=0)
    last_donation = models.DateTimeField(default=timezone.now)
    blood_group = models.CharField(max_length=20, choices=BLOOD_GROUP_CHOICES, default=None, null=True)
    available = models.BooleanField(default=False, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'fullname']

    objects = CustomUserManager()

    def __str__(self):
        return self.username + ": " + self.email


class EmailToken(models.Model):
    email = models.EmailField('email address', unique=True)
    token = models.IntegerField()

    REQUIRED_FIELDS = ['email', 'token']

    def __str__(self):
        return self.email
