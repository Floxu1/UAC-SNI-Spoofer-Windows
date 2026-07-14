# UAC Spoofer Desktop

## English

### What it is
UAC Spoofer Desktop is a Windows network dashboard built around Xray and the Patterniha SNI-spoofing method. It manages carrier-specific routes, scans and ranks SNI/Edge pairs, applies the Windows proxy, and restores the previous proxy state when the app exits.

The desktop profiles are tuned separately for **MCI / Hamrah Aval** and **IranCell**, so changing one carrier does not overwrite the other carrier's settings.

### Features
- Separate MCI, IranCell, and Auto carrier modes
- Xray-based local SOCKS/HTTP tunnel
- Patterniha SNI/Edge scanner with live results
- MCI TLS-record startup optimization and YouTube warmup
- Suggested-config ranking using real page and bounded download checks
- Persian and English interface with RTL/LTR handling
- App Bypass, live logs, public-IP check, and advanced tuning
- GitHub Releases update checker
- Transactional Windows proxy restore after disconnect, exit, or restart

### Portable version
1. Download `UAC-Spoofer-Desktop-v1.0.0-Windows-x64.zip` from GitHub Releases.
2. Extract the complete archive; keep the `_internal` folder beside the EXE.
3. Run `UAC-Spoofer-Desktop.exe` and accept the Windows UAC prompt.

Python is not required for the portable build.

### Run from source
Requirements: Windows 10/11 x64 and Python 3.11 or 3.12.

```powershell
python -m pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File .\install-engine.ps1
python main.py
```

### Carrier mode
- `mci`: independent MCI/Hamrah Aval route, SNI, Edge, benchmarks, and tuning.
- `irancell`: independent IranCell route and tuning.
- `auto`: the app-managed general profile. For deterministic results, select the current carrier explicitly.

### Updates
Project repository: `https://github.com/Floxu1/UAC-SNI-Spoofer-Windows`

- Current version: `1.0.0` in `uac_desktop/__init__.py`
- Update repository: `UPDATE_REPOSITORY_URL` in `uac_desktop/app_config.py`
- Latest-release endpoint: `https://api.github.com/repos/Floxu1/UAC-SNI-Spoofer-Windows/releases/latest`
- Release and portable URLs are derived from that repository.

Publish a GitHub Release tagged `v1.0.0` and upload the Windows x64 ZIP. Runtime release parsing is handled by `check_latest_release()` in `uac_desktop/update_checker.py`; future published tags such as `v1.0.1` are detected automatically.

### Credits
Special thanks to the **Patterniha** group for inventing and introducing this SNI-spoofing method. The integrated upstream source and GPL-3.0 license are included under `third_party/patterniha_sni_spoofing/`.

---

## فارسی

### این برنامه چیه؟
UAC Spoofer Desktop یه داشبورد شبکه برای ویندوزه که با Xray و روش SNI Spoofing گروه Patterniha کار می‌کنه. برنامه مسیر مناسب رو پیدا می‌کنه، SNI و Edgeها رو تست و مرتب می‌کنه، پروکسی ویندوز رو خودش تنظیم می‌کنه و موقع قطع اتصال یا بستن برنامه، تنظیم قبلی پروکسی رو برمی‌گردونه.

تنظیمات **همراه اول** و **ایرانسل** کاملاً جدا نگه داشته می‌شن؛ یعنی تنظیم یکی، اون یکی رو به‌هم نمی‌ریزه. هر دو اپراتور با پروفایل مخصوص خودشون پشتیبانی می‌شن.

### قابلیت‌ها
- حالت جدا برای همراه اول، ایرانسل و Auto
- تونل محلی Xray با SOCKS و HTTP
- آزمایشگاه SNI با نمایش زنده نتیجه‌ها
- بهینه‌سازی شروع TLS و گرم‌کردن مسیر YouTube برای همراه اول
- پیشنهاد بهترین کانفیگ با تست واقعی صفحه و دانلود کوتاه
- رابط فارسی و انگلیسی با چیدمان درست RTL و LTR
- App Bypass، لاگ زنده، بررسی IP و تنظیمات پیشرفته
- بررسی آپدیت از GitHub Releases
- برگردوندن امن تنظیمات پروکسی ویندوز بعد از قطع یا بستن برنامه

### اجرای نسخه Portable
1. فایل `UAC-Spoofer-Desktop-v1.0.0-Windows-x64.zip` رو از بخش Releases بگیر.
2. کامل Extract کن؛ پوشه `_internal` باید کنار فایل EXE بمونه.
3. `UAC-Spoofer-Desktop.exe` رو اجرا کن و پیام UAC ویندوز رو تأیید کن.

برای نسخه Portable اصلاً لازم نیست Python نصب باشه.

### اجرای سورس
روی Windows 10/11 نسخه 64 بیتی و Python 3.11 یا 3.12:

```powershell
python -m pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File .\install-engine.ps1
python main.py
```

### Carrier Mode خیلی خلاصه
- `mci`: تنظیم، Edge، SNI و تست‌های مخصوص همراه اول.
- `irancell`: تنظیم و مسیر جدا برای ایرانسل.
- `auto`: حالت عمومی خودکار؛ برای نتیجه دقیق‌تر بهتره اپراتور فعلی رو دستی انتخاب کنی.

### تنظیم آپدیت
آدرس پروژه روی `https://github.com/Floxu1/UAC-SNI-Spoofer-Windows` تنظیم شده و نسخه فعلی `1.0.0` هست. برنامه آخرین Release منتشرشده رو از تگ‌های همین مخزن چک می‌کنه. آدرس مخزن داخل `uac_desktop/app_config.py` و شماره نسخه داخل `uac_desktop/__init__.py` قرار داره. برای شروع یک Release با تگ `v1.0.0` منتشر کن؛ نسخه‌های بعدی مثل `v1.0.1` خودکار شناسایی می‌شن.

### تشکر
یه تشکر ویژه از گروه **Patterniha** بابت اختراع و معرفی این متد SNI Spoofing. سورس اصلی و لایسنس GPL-3.0 داخل `third_party/patterniha_sni_spoofing/` قرار گرفته.
