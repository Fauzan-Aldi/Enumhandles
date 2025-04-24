# enumhandles_BOF
ini dapat digunakan untuk mengidentifikasi proses yang memegang pegangan pada file tertentu. Ini dapat berguna untuk mengidentifikasi proses mana yang mengunci file pada disk.

# Keterbatasan
Saya telah menemukan bahwa beacon x86 terkadang akan macet ketika mencoba untuk mencacah handle yang terkait dengan image x64. Sebagai contoh, menjalankan `enumhandles c:\windows\sysnative\svchost.exe` dapat menyebabkan crash.
