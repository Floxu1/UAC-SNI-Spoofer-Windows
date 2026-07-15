# UAC SNI Spoofer Windows

## زبان / Language

**فارسی** | [English](./README.en.md)

---
[کانال تلگرام](https://t.me/UacSniSpoofer): `t.me/UacSniSpoofer`

---
<a href="https://floxu1.github.io/UAC-SNI-Spoofer-Windows/" 
style="display:inline-block;padding:10px 20px;background:#24292f;color:white;text-decoration:none;border-radius:8px;"
target="_blank">
آموزش ساده و قدم به قدم راه اندازی و استفاده از نرم‌افزار UAC Sni spoofing نسخه ویندوز

---
## معرفی برنامه

نرم افزار UAC SNI Spoofer Windows یک داشبورد شبکه برای ویندوز است که با استفاده از Xray و متد SNI Spoofing گروه Patterniha کار می‌کنه.

این برنامه مسیرهای مخصوص هر اپراتور را مدیریت می‌کنه، SNI و Edgeهای مختلف را بررسی و رتبه‌بندی میکنه، پروکسی ویندوز را به‌صورت خودکار اعمال میکنه و هنگام قطع اتصال یا خروج از برنامه، تنظیمات قبلی پروکسی را بازمی‌گرداند.

پروفایل‌های برنامه برای **همراه اول / MCI** و **ایرانسل / IranCell** به‌صورت جداگانه تنظیم شده‌اند؛ بنابراین تغییر تنظیمات یک اپراتور باعث تغییر یا خراب شدن تنظیمات اپراتور دیگر نمی‌شود.
<img width="1418" height="908" alt="image" src="https://github.com/user-attachments/assets/1ab70b55-ce69-4fa2-bbcf-d501c1915b47" />


## قابلیت‌ها

- حالت‌های جداگانه برای همراه اول، ایرانسل و حالت Auto
- تونل محلی مبتنی بر Xray با پشتیبانی از SOCKS و HTTP
- اسکن و رتبه‌بندی SNI و Edge با نمایش نتیجه‌های زنده
- بهینه‌سازی شروع اتصال TLS برای همراه اول
- گرم‌سازی مسیر YouTube برای بهبود شروع پخش ویدیو
- پیشنهاد بهترین تنظیمات بر اساس تست واقعی صفحه و دانلود محدود
- رابط کاربری فارسی و انگلیسی با پشتیبانی از چیدمان RTL و LTR
- قابلیت App Bypass
- نمایش لاگ زنده
- بررسی IP عمومی
- تنظیمات پیشرفته برای مسیر، SNI، DNS، Timeout و Fallback
- بررسی نسخه جدید از طریق GitHub Releases
- بازگردانی امن تنظیمات پروکسی ویندوز پس از قطع اتصال، خروج یا راه‌اندازی مجدد برنامه

## پشتیبانی از اپراتورها

این برنامه برای دو اپراتور زیر تنظیم و بهینه‌سازی شده:

- همراه اول / MCI
- ایرانسل / IranCell

در حالت `mci` تنظیمات مربوط به همراه اول به‌صورت مستقل استفاده می‌شود. در حالت `irancell` نیز تنظیمات ایرانسل جداگانه نگهداری می‌شود. برای دریافت نتیجه پایدارتر، بهتر است اپراتور فعلی به‌صورت دستی انتخاب شود.

## اجرای نسخه Portable

نسخه Portable برای کاربرانی آماده شده که نمی‌خواهند Python یا وابستگی‌های جانبی نصب کنند.

مراحل اجرا:

1. فایل زیر را از بخش GitHub Releases دانلود کنید:
<a href="https://github.com/Floxu1/UAC-SNI-Spoofer-Windows/releases/download/1.0.0/UAC-Spoofer-Desktop-v1.0.0-Windows-x64.zip" target="_blank">
UAC-Spoofer-Desktop-Windows-x64.zip
</a>


2. فایل ZIP را کامل Extract کنید.
3. پوشه `_internal` باید کنار فایل اجرایی باقی بماند.
4. فایل زیر را اجرا کنید:

```text
UAC-Spoofer-Desktop.exe
```
<a href="https://floxu1.github.io/UAC-SNI-Spoofer-Windows/" 
style="display:inline-block;padding:10px 20px;background:#24292f;color:white;text-decoration:none;border-radius:8px;"
target="_blank">
آموزش ساده و قدم به قدم راه اندازی و استفاده از نرم‌افزار UAC Sni spoofing نسخه ویندوز
</a>

5. در صورت نمایش پیام UAC ویندوز، آن را تأیید کنید.
ا
برای اجرای نسخه Portable نیازی به نصب Python نیست.

## اجرای نسخه سورس

پیش‌نیازها:

- Windows 10/11 نسخه 64 بیتی
- Python نسخه 3.11 یا 3.12

دستورهای اجرا:

```powershell
python -m pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File .\install-engine.ps1
python main.py
```

## حالت Carrier Mode

برنامه دارای چند حالت اپراتور است:

- `mci`: تنظیمات مستقل مخصوص همراه اول، شامل Route، SNI، Edge، تست‌ها و بهینه‌سازی‌ها
- `irancell`: تنظیمات و مسیر مستقل مخصوص ایرانسل
- `auto`: حالت عمومی و خودکار برنامه

برای نتیجه دقیق‌تر و پایدارتر، بهتر است اپراتور فعلی به‌صورت دستی انتخاب شود.


## تشکر و اعتبار

از گروه **Patterniha** بابت اختراع و معرفی متد SNI Spoofing تشکر می‌شود.

سورس اصلی و لایسنس GPL-3.0 در مسیر زیر قرار دارد:

```text
third_party/patterniha_sni_spoofing/
```
---
## لایسنس

این پروژه تحت لایسنس **GNU General Public License v3.0 (GPL-3.0)** منتشر شده است.

شما می‌توانید برنامه را استفاده، بررسی و تغییر دهید، اما در صورت انتشار نسخه تغییر‌یافته یا مشتق‌شده، باید شرایط GPL-3.0 را رعایت کنید، سورس کد را در دسترس قرار دهید و همین لایسنس را حفظ کنید.

متن کامل لایسنس در فایل [LICENSE](LICENSE) قرار دارد.
