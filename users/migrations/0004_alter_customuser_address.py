# Generated by Django 4.0.4 on 2022-05-16 06:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0003_customuser_available'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='address',
            field=models.CharField(choices=[('achham', 'achham'), ('arghakhanchi', 'arghakhanchi'), ('baglung', 'baglung'), ('baitadi', 'baitadi'), ('bajhang', 'bajhang'), ('bajura', 'bajura'), ('banke', 'banke'), ('bara', 'bara'), ('bardiya', 'bardiya'), ('bhaktapur', 'bhaktapur'), ('bhojpur', 'bhojpur'), ('chitwan', 'chitwan'), ('dadeldhura', 'dadeldhura'), ('dailekh', 'dailekh'), ('dang deukhuri', 'dang deukhuri'), ('darchula', 'darchula'), ('dhading', 'dhading'), ('dhankuta', 'dhankuta'), ('dhanusa', 'dhanusa'), ('dholkha', 'dholkha'), ('dolpa', 'dolpa'), ('doti', 'doti'), ('gorkha', 'gorkha'), ('gulmi', 'gulmi'), ('humla', 'humla'), ('ilam', 'ilam'), ('jajarkot', 'jajarkot'), ('jhapa', 'jhapa'), ('jumla', 'jumla'), ('kailali', 'kailali'), ('kalikot', 'kalikot'), ('kanchanpur', 'kanchanpur'), ('kapilvastu', 'kapilvastu'), ('kaski', 'kaski'), ('kathmandu', 'kathmandu'), ('kavrepalanchok', 'kavrepalanchok'), ('khotang', 'khotang'), ('lalitpur', 'lalitpur'), ('lamjung', 'lamjung'), ('mahottari', 'mahottari'), ('makwanpur', 'makwanpur'), ('manang', 'manang'), ('morang', 'morang'), ('mugu', 'mugu'), ('mustang', 'mustang'), ('myagdi', 'myagdi'), ('nawalparasi', 'nawalparasi'), ('nuwakot', 'nuwakot'), ('okhaldhunga', 'okhaldhunga'), ('palpa', 'palpa'), ('panchthar', 'panchthar'), ('parbat', 'parbat'), ('parsa', 'parsa'), ('pyuthan', 'pyuthan'), ('ramechhap', 'ramechhap'), ('rasuwa', 'rasuwa'), ('rautahat', 'rautahat'), ('rolpa', 'rolpa'), ('rukum', 'rukum'), ('rupandehi', 'rupandehi'), ('salyan', 'salyan'), ('sankhuwasabha', 'sankhuwasabha'), ('saptari', 'saptari'), ('sarlahi', 'sarlahi'), ('sindhuli', 'sindhuli'), ('sindhupalchok', 'sindhupalchok'), ('siraha', 'siraha'), ('solukhumbu', 'solukhumbu'), ('sunsari', 'sunsari'), ('surkhet', 'surkhet'), ('syangja', 'syangja'), ('tanahu', 'tanahu'), ('taplejung', 'taplejung'), ('terhathum', 'terhathum'), ('udayapur', 'udayapur')], default=None, max_length=400, null=True, verbose_name='address'),
        ),
    ]
