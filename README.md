# Testing ID

Mustaqil OneID contract mock. Faqat sun’iy test hisoblari uchun. Mavjud `mening_fikrim`, Keycloak yoki eski `oneid-mock` loyihalariga dependency yo‘q; haqiqiy OneID’ga so‘rov yubormaydi.

Python 3.12+, FastAPI, SQLite va bitta Uvicorn worker ishlatiladi. `uv.lock` development/test dependencylarini, `requirements.lock` hashlar bilan Docker runtime dependencylarini muzlatadi. HTTP kontrakti va hujjatdagi noaniqliklar [CONTRACT.md](CONTRACT.md)da.

## Lokal Docker bilan boshlash

Docker/Compose va testlar uchun `uv` kerak. Loyiha rootidan:

```bash
cp .env.example .env
make install
make test
make check
make build
make up
make docker-init
make health
```

`make docker-init` faqat bo‘sh database uchun. Ikki client (`petition-dev`, `cabinet-dev`) va 14 sun’iy hisob yaratadi. Login/parol/client secretlar `.local/docker-credentials.json`ga 0600 huquq bilan saqlanadi; qiymatlar terminalga chiqarilmaydi. Ularni faylni lokal ochib oling, chat/log/Gitga ko‘chirmang. Default callback `https://client.example.test/callback` — faqat kontrakt testi uchun placeholder, ishlaydigan Mening Fikrim callback’i emas.

Xizmat: `http://localhost:8089`. Root sahifa faqat ma’lumot beradi; loginni client o‘zining OAuth URL’i bilan boshlaydi. Port band bo‘lsa `.env`dagi `MOCK_PORT`ni o‘zgartiring; `MOCK_PUBLIC_BASE_URL` va smoke manzili ham mos bo‘lsin. Servis hostda faqat loopback orqali ochiladi.

Real consumer callback’i ma’lum bo‘lganda default hisoblarni reset qilmasdan alohida client qo‘shing:

```bash
docker compose exec -T app python -m app.cli add-client mening-fikrim-dev \
  --redirect-uri https://api-petition.dgov-uic.uz/api/identity/providers/oneid/callback \
  --scope mening-fikrim-dev \
  --credentials-file /data/mening-fikrim-client.json
docker compose cp app:/data/mening-fikrim-client.json .local/mening-fikrim-client.json
chmod 600 .local/mening-fikrim-client.json
```

Bu callback taklif qilingan misol; consumer loyihada ushbu route borligi avtomatik taxmin qilinmaydi. Client id, scope va callback exact mos kelishi kerak. HTTP/localhost/loopback callback ro‘yxatdan o‘tkazilmaydi. Username `disabled` dastlab o‘chirilgan, qolganlarining nomlari fixture ssenariysini bildiradi. [Profillar](app/profiles.py).

## Haqiqiy HTTP smoke

```bash
uv run --frozen python scripts/smoke.py
```

Mockning HTTP health identifikatori tekshirilgachgina sun’iy credentials ishlatiladi. Authorization → login → token → profil → logout sinovi callback’ni kuzatmaydi va boshqa backendga so‘rov yubormaydi. Bu script brauzerning SameSite yoki CSP siyosatini emulyatsiya qilmaydi; ular alohida browser qabulida tekshiriladi.

## Bepul public HTTPS

[Cloudflare Quick Tunnel](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/) akkaunt/domensiz vaqtinchalik HTTPS manzil beradi. Bir Quick Tunnel to‘xtab qayta yaratilsa hostname o‘zgaradi; uptime kafolati yo‘q. OAuth backchannel so‘rovlariga interaktiv email login darvozasi qo‘shilmaydi.

```bash
make tunnel
make tunnel-url
```

Chiqqan aniq URL’ni **shu loyiha** `.env`idagi `MOCK_PUBLIC_BASE_URL`ga yozing, masalan `https://example.trycloudflare.com`. Keyin **faqat app**ni yangilang:

```bash
docker compose up -d --no-deps app
make health
uv run --frozen python scripts/smoke.py --base-url https://example.trycloudflare.com
```

Bu yerda tunnel qayta yaratilmaydi. Database va credentials named volume’da qoladi. Login sahifasini ham public HTTPS URL orqali oching: Origin tekshiruvi `MOCK_PUBLIC_BASE_URL`ga mos. URL o‘zgarsa consumerning OneID base URL’i ham yangilanadi; client secret va hisoblar almashtirilmaydi. `MOCK_PUBLIC_BASE_URL` mockning manzili, `redirect_uri` esa client backend callback’i — ular alohida.

HTTPS muhitda mock browser cookie’si `__Host-testing_id_browser`, Secure, HttpOnly, Path=/, SameSite=Lax, Domain’siz bo‘ladi. Lokal HTTP’da prefikssiz cookie ishlatiladi. Mock endpointlarida wildcard CORS yo‘q; authorization browser navigatsiyasi, token/profil/logout server-to-server POST hisoblanadi.

## Docker’siz ishlab chiqish

```bash
make install
make init
make run
```

Bu rejim `.local/data/testing-id.sqlite3` va `.local/credentials.json`dan foydalanadi; Docker named volume’dan alohida. Bir xil portda Docker va lokal Uvicorn’ni bir vaqtda yoqmang. O‘zgaruvchilarni `.env` yoki process environment orqali bering. Init mavjud ma’lumotlarni qayta seed qilmaydi, credentials faylini almashtirmaydi.

## X-app deployment

Alohida papka: `/home/user01/projects/backend/testing-id`. Git `origin`: `https://github.com/XojiakbarMadaminov/testing-id.git`. Dastlabki deployment manba fayllarini SSH/rsync bilan ko‘chiradi; GitHub’ga push qilmaydi. `.env`, `.local`, SQLite va credentials boshqa loyihadan olinmaydi. Serverning loopback `8089` porti, Compose project va volume faqat `testing-id`ga tegishli. Serverda mustaqil credentials yaratiladi; lokal hisoblarning parollari serverga mos kelmaydi.

```bash
ssh x-app
cd /home/user01/projects/backend/testing-id
docker compose ps
make health
make tunnel-url
python3 scripts/smoke.py --base-url https://TUNNEL-MANZILI.trycloudflare.com
```

Docker ishga tushirish uchun hostda `uv` kerak emas; `make tunnel-url` va smoke script Python 3 standard library bilan ishlaydi. `uv` faqat Docker’siz development/test uchun ishlatiladi. Server credentials fayli `.local/docker-credentials.json`; uni chat yoki logga chiqarmang. Consumer backend sozlamasida serverdagi tunnel manzilini ishlating. Mock root sahifasi loginni o‘zi boshlamaydi: client o‘z credentials/scope va ro‘yxatdan o‘tgan callback’i bilan authorization URL yaratadi.

Mavjud Keycloak, `navoi-airport/oneid-mock`, Mening Fikrim, Nginx yoki boshqa Compose projectlarining konfiguratsiyasi o‘zgartirilmaydi. Oldingi mockning container/image/volume nomlari ishlatilmaydi. Keyinchalik tashkilot nazoratidagi doimiy HTTPS subdomen yoki named tunnel bilan Quick Tunnel o‘rnini almashtirish mumkin.

```bash
make down
```

Faqat shu project konteynerlari to‘xtaydi; volume saqlanadi. `down -v`, database reset yoki credential faylini o‘chirib initni takrorlash odatiy ishga tushirish qadami emas. GitHub’ga kod chiqarish alohida user qadami; source yangilanishidan keyin `docker compose build app` va `docker compose up -d --no-deps app` yetarli, init takrorlanmaydi.

## Doimiy Cloudflare domeniga o‘tish

Quick Tunnel uchun foydalanuvchidan akkaunt/token/DNS sozlamasi talab qilinmaydi. Barqaror hostname kerak bo‘lsa [Cloudflare Tunnel qo‘llanmasi](https://developers.cloudflare.com/tunnel/get-started/) asosida:

1. O‘zingiz boshqaradigan domenni Cloudflare akkauntiga ulang.
2. Dashboard’dagi Networking → Tunnels orqali alohida `testing-id` named tunnel yarating.
3. Published application route uchun, masalan, `testing-id.example.uz` hostname belgilang. Connector shu Compose tarmog‘ida ishlatilsa service URL `http://app:8080`; host network’da ishlatilsa `http://127.0.0.1:8089`. Oddiy alohida Docker konteyneridagi `localhost` app manzilini anglatmaydi.
4. Connector tokenini serverdagi private faylda saqlang; Git yoki chatga yubormang. Shu tunnel uchun alohida connector ishga tushiriladi; mavjud eski mock connectori o‘zgartirilmaydi. OAuth endpointlariga interaktiv Cloudflare Access/email login qo‘ymang: backend token/profil so‘rovlari undan o‘ta olmaydi.
5. Shu loyiha `.env`ida `MOCK_PUBLIC_BASE_URL=https://testing-id.example.uz` qiling va faqat appni recreate qiling. Consumer base URL’ini ham yangilang, HTTPS smoke bajaring; undan so‘ng eski Quick Tunnel’ni to‘xtating. Database/client secretlar o‘zgarmaydi.

Named tunnel sozlamasi uchun tanlangan domen va Cloudflare akkauntidagi tunnel yaratilishi kerak; ularni bilmasdan DNS yoki mavjud connectorlarga o‘zgartirish kiritilmaydi. Serverga kiruvchi yangi public port ochish talab qilinmaydi; connector uchun Cloudflare’ga chiquvchi `7844/TCP` (bu loyihada HTTP/2) ruxsati kerak.

## Consumer integratsiyasi chegarasi

Saloon integratsiyasi aynan hujjatdagi requestlarni yuborishi, state’ni o‘z sessionida tekshirishi, `ret_cd`, `valid`, `validation_method` va PINFL’ni tekshirishi kerak. PHP’da `(bool) "false"` qilish mumkin emas; `string-false` aynan shu xatoni sinash uchun bor. `email_verified` yoki OIDC `sub` bu kontraktdagi tasdiqlangan PINFL o‘rnini bosmaydi.

Haqiqiy OneID’ga ko‘chishda base URL, operator bergan client credentials/scope va ro‘yxatdan o‘tgan callback konfiguratsiyasi yangilanadi. Mockdan o‘tgan test haqiqiy provayderning qabul sinovi o‘rnini bosmaydi. Mock faqat dev/test consumerda ishlatiladi.

Localhost frontend uchun mavjud HTTPS Vite proxy API so‘rovlarini uzata oladi. Hujjat localhost callback’ni rad etadi: API domenidagi callback’da o‘rnatilgan cookie localhostga ko‘chmaydi. Consumer integratsiyasida same-site lokal frontend yoki alohida xavfsiz callback/session handoff dizayni kerak; bu mock loyihasi mavjud consumer auth kodini o‘zgartirmaydi.

