طيب خلينا نكون واقعيين .. المطورين بنسبة كبيرة بتعمل validation بشكل او بإخر .. اي انوع ال validations؟

- Client-side validation
ودا من اعبط ال validations لأنه من ال client side يعني من المتصفح مش من الباك اند وبالتالي استخدام اي proxy زي burp suite ممكن يتخطي ال validation دا ويبعته عادي!


ال validation بالشكل دا:
![](content-type-validation.png)

- Content-Type Validation
ودي عملية تحقق من قيمة ال `Content-Type` header يعني لو بترفع صورة `.jpeg` هيكون بالشكل دا:

```
Content-Type: image/jpeg
```

طبعا مش عاوز اقولك انه برضو سهل التلاعب فيه ووضع اي قيمة بإستخدام اي proxy وبالتالي علي المبرمج انه يتحقق منه من حاجات اخر ومش يعتمد عليه فقط.


- Signature Validation
ودي عملية تحقق من محتوي الملف نفسه وبيكون التحقق في الغالب علي اول 4 او 6 bytes علشان يتأكد انه الملف دا فعلا gif علي سبيل المثال .. لازم يتأكد انه اول 6 bytes منه هم: [`47 49 46 38 37 61` او `47 49 46 38 39 61`](https://www.ntfs.com/gif-signature-format.htm)



- Blacklist dangerous file types
ودا معناه انه بيعمل مثلا لستة بال extensions الممنوع استخدامها. مثلا بالشكل التالي:

```python
blacklist_exts = ["php", "jsp", "html", "js"]
```


بس فكر فيها .. منطقي انه يحط كل ال extensions الممنوعة واللي ممكن توصل لأكتر من ألف امتداد؟ ولا المنطقي اكتر انه يعمل لستة بالامتدادات المسموحة؟ صح؟ مش دا الأكثر امانا؟

- Whitelist file types

```python
whitelist_exts = ["png", "jpg", "jpeg", "gif"]

if(uploaded_file_ext not in whitelist_exts):
	# block the request
```

ويبدأ بقا يتأكد لو امتداد الملف مش من دول اذا يمنع الريكويست زي ما في الكود!
