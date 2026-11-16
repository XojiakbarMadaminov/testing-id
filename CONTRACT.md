# OneID HTTP kontrakti va mock qarorlari

Asos: foydalanuvchi bergan `TexnologikYoriqnoma.docx`, 4.1–4.4 bo‘limlar. Bu loyiha avvalgi Keycloak/OIDC simulator emas. Real OneID base URL: `https://sso.egov.uz`; mockda base URL konfiguratsiyadan olinadi. Endpoint har ikki holatda `/sso/oauth/Authorization.do`.

| Amal | Method | Majburiy parametrlar |
|---|---|---|
| Authorization | GET | response_type=one_code, client_id, redirect_uri, scope, state |
| Code exchange | POST form | grant_type=one_authorization_code, client_id, client_secret, redirect_uri, code |
| Identify | POST form | grant_type=one_access_token_identify, client_id, client_secret, access_token, scope |
| Logout | POST form | grant_type=one_log_out, client_id, client_secret, access_token, scope |

POST `application/x-www-form-urlencoded` bilan. Client secret brauzer authorization URL’iga qo‘yilmaydi. Authorization javobi registered callback’ga `code`/`state` query bilan qaytadi. Oldindan ro‘yxatdan o‘tmagan URL’ga error redirect ham qilinmaydi. Mavjud callback query parametrlari saqlanadi; code/state collisionli callback qabul qilinmaydi.

Token javobi: `access_token`, `refresh_token`, `token_type=bearer`, `expires_in`, `scope`. Tokenlar opaque qiymat; JWT/ID token/JWKS/discovery talab qilinmaydi. Code va tokenlarda base64 `+`, `/`, `=` belgilari bo‘lishi mumkin; consumer form/query encodingni to‘g‘ri ishlatishi kerak.

Profil: `valid`, `validation_method`, `pin`, `user_id`, `full_name`, `pport_no`, `birth_date`, `sur_name`, `first_name`, `mid_name`, `user_type`, `sess_id`, `ret_cd`, `auth_method`; tegishli fixture’da `pkcs_legal_tin` va `legal_info`. Mockning ichki user/client id’lari integer, `sess_id` esa hujjat talab qilgan provider UUID string. Ismlar consumerga birlashtirilmagan holda alohida keladi. Profil user boshqaruv CLI’si orqali seed qilingan fixture’dan olinadi; browser arbitrary profile yoki PINFL yuborib uni almashtira olmaydi.

## Aniq hujjatlashtirilmagan joylar

- `valid` jadvalda Boolean, namuna JSON’da string. Default `true` Boolean; `string-true` va `string-false` test variantlari bor.
- `birth_date` jadvalda yyyy-MM-dd, namunada yyyyMMdd. Default ISO date; `legacy-date` fixture ikkinchi variantni beradi.
- `refresh_token` javobda bor, ammo refresh request kontrakti berilmagan. Mock token qaytaradi va hash/expiry saqlaydi; refresh grant implement qilinmagan. Taxminiy `one_refresh_token` yoki standart `refresh_token` grant 400 unsupported_grant_type oladi.
- Logout javobi ko‘rsatilmagan. Mock konvensiyasi: HTTP200 `{"ret_cd":"0"}`; qayta logout invalid_token. Bu real OneID javobi tasdiqlanganini anglatmaydi.
- Xato HTTP status/body’lari berilmagan. Mock konvensiyasi: OAuth `error`/`error_description`; invalid_request/invalid_grant/unsupported_grant_type 400, invalid_client/invalid_token 401, Origin rad etilishi 403, login limit 429 va storage xatosi 503. Payload/secretlar aks ettirilmaydi.
- Mock defaultlari: code60s, access300s, refresh86400s, login request300s, browser SSO3600s. Bular haqiqiy OneID TTL’lari emas. Defaultlar `MOCK_*_TTL` orqali boshqariladi.

## Mockdagi qo‘shimcha xavfsizlik va test qarorlari

Redirect faqat exact registered HTTPS URL. Hujjatdagi localhost taqiqini loopback IP va `.localhost`larga ham qo‘llaymiz. Scopelar clientga tegishli exact qiymatlar; `openid profile email` avtomatik qabul qilinmaydi. Client auth faqat POST form orqali, Authorization header orqali emas.

Login sahifasining ichki POST `/login` amali provider UI’ga tegishli; consumer uni bevosita chaqirmaydi. Browser cookie + CSRF + exact Origin tekshiruvi, login paytida cookie rotation va rate limit bor. SSO faqat shu sun’iy browser session doirasida. SQLite transactioni bir koddan bir nechta token chiqarishni rad etadi; restart kodni qayta ishlatishga ruxsat bermaydi.

Mock logout taqdim etilgan tokenning browser sessionini, shu browserga tegishli tokenlar va pending kodlarni bekor qiladi. Boshqa browser sessiyalariga tegmaydi. Bu global/provider logout ko‘lami real OneID hujjatida aniqlanmagani uchun mock qarori hisoblanadi. Disabled client token amallariga, disabled user esa profil/SSO/kod almashinuviga kiritilmaydi.

Public yuzalar faqat `/`, `/health`, `/static`, GET/POST contract endpoint va provider UI `/login`. Public management API yo‘q. UI OneID’ning rasmiy brend sahifasini taqlid qilmaydi va test muhiti ekanini ko‘rsatadi. ERI/Mobile-ID/QR integratsiyasi emas, ularning natija profillari simulyatsiyasi bor.
