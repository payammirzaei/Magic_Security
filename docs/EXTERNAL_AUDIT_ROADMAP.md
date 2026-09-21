# External Audit Pipeline Roadmap

این سند مسیر تبدیل Magic Security به یک pipeline وب برای audit امن و evidence-driven سایت‌های ساخته‌شده با ابزارهای vibe coding را مشخص می‌کند.

هدف محصول این نیست که با چند request یک اسکنر checklist محور بسازد. هدف این است که یک target را بگیرد، سطح حمله را مرحله‌به‌مرحله بسازد، تست‌های قابل اثبات اجرا کند، evidence را نگه دارد و نتیجه را با confidence، severity و محدودیت‌هایش نشان دهد.

## وضعیت فعلی

### Backend

- FastAPI و SQLite وجود دارد.
- target، scan، finding، snapshot و baseline ذخیره می‌شوند.
- موتور فعلی discovery، browser، API، auth و security packهای مختلف دارد.
- report JSON و HTML تولید می‌شود.
- baseline diff برای scanهای بعدی وجود دارد.

### Frontend

- React/Vite SPA با صفحه‌های Home، Targets، New Scan، History و Scan Detail وجود دارد.
- کاربر می‌تواند scan را شروع کند و با polling وضعیت آن را بگیرد.
- finding، coverage، attack surface و baseline diff نمایش داده می‌شوند.
- production build فعلی موفق است.

### محدودیت‌های مهم

- job با `asyncio.create_task` داخل همان process اجرا می‌شود و queue/worker/retry ندارد.
- scan بعد از restart شدن server قابل اتکا نیست.
- user، workspace، project و authorization وجود ندارد.
- pipeline stageهای واقعی و progress قابل مشاهده ندارد.
- auth context از مسیر فایل روی server گرفته می‌شود؛ برای محصول وب مناسب نیست.
- SQLite برای اجرای محلی است و لایه production persistence نیست.
- browser execution به نصب Chromium وابسته است.

## مدل محصول

جریان اصلی باید این باشد:

```text
Workspace → Project → Target → Audit Run → Stages → Evidence → Findings → Report → Re-scan
```

هر finding باید حداقل این اطلاعات را داشته باشد:

- `category`: vulnerability، exposure، hardening یا observation
- `severity`: critical، high، medium، low یا info
- `confidence`: verified، strong-signal یا requires-workflow
- `check_id` و fingerprint پایدار
- endpoint یا resource مربوط
- evidence قابل مشاهده و redacted
- مراحل و تست‌هایی که اجرا شده‌اند
- remediation قابل اقدام
- محدودیت تشخیص و علت false-negative احتمالی

## قابلیت‌های باقی‌مانده و روش پیاده‌سازی

### 1. Pipeline و اجرای پایدار job

**هدف:** اجرای audit مستقل از request و process وب.

**پیاده‌سازی:**

1. مدل‌های `audit_runs`، `audit_stages` و `audit_events` به persistence اضافه شوند.
2. scan به stageهای مستقل تقسیم شود: `preflight`، `discovery`، `browser`، `api`، `authz`، `config`، `validation` و `report`.
3. برای نسخه اول یک worker process مبتنی بر SQLite قابل‌قبول است؛ اجرای production باید به Postgres + Redis/queue منتقل شود.
4. هر stage وضعیت `queued/running/completed/failed/skipped`، زمان شروع/پایان، counters و خطا داشته باشد.
5. retry فقط برای خطاهای transient انجام شود و هر retry idempotent باشد.
6. endpointهای `GET /runs/{id}` و `GET /runs/{id}/events` برای progress اضافه شوند؛ در frontend بعداً SSE یا WebSocket جای polling را بگیرد.

### 2. Target و deployment discovery

**هدف:** پیدا کردن سطح حمله واقعی قبل از اجرای checkها.

**پیاده‌سازی:**

- DNS records، certificate SAN و redirect chain جمع‌آوری شوند.
- subdomainها فقط از منابع passive و منابع مجاز target استخراج شوند.
- dangling DNS و origin leak با DNS/HTTP evidence محدود بررسی شوند.
- `robots.txt`، sitemap، security.txt، well-knownها، manifestها، service worker و public storage URLها به surface graph اضافه شوند.
- `.git`، `.svn`، backup و debug artifactها با HEAD یا prefix محدود probe شوند.
- scope policy قبل از هر request اعمال شود؛ private IP، metadata endpoint و خارج شدن از host مجاز مسدود بماند.

### 3. HTTP، TLS و proxy behavior

**هدف:** پیدا کردن ضعف‌های deployment و edge بدون exploit تهاجمی.

**پیاده‌سازی:**

- TLS version، certificate hostname، expiry و redirect به HTTPS بررسی شود.
- HSTS، CSP، COOP، COEP، CORP، Referrer-Policy و Permissions-Policy بررسی شوند.
- تفاوت response در HTTP/1.1 و HTTP/2، host header و methodهای غیرمنتظره با requestهای محدود مقایسه شود.
- cache headers، private response caching، cache key و unsafe variation signal ثبت شوند.
- برای request smuggling و desync فقط passive/low-risk indicators گزارش شوند مگر workflow آزمایشی صریح وجود داشته باشد.

### 4. Frontend و client artifact audit

**هدف:** بررسی bundleها و رفتار browser که در سایت‌های vibe-coded محل رایج نشت است.

**پیاده‌سازی:**

- همه script، source map، preload، worker و dynamic importها inventory شوند.
- secret-like token، private key، cloud credential، internal hostname و debug flag با redaction پیدا شوند.
- نسخه framework و dependency از bundle و manifest استخراج شود و با advisory database قابل به‌روزرسانی مقایسه گردد.
- source/sink analysis برای DOM XSS، open redirect، unsafe postMessage، prototype pollution و client-side template injection توسعه یابد.
- runtime browser evidence از storage key names، network destinations، iframeها، service worker و WebSocketها ثبت شود؛ مقدار secret هرگز در report ذخیره نشود.

### 5. API و GraphQL audit

**هدف:** مدل‌کردن API واقعی، نه فقط endpointهای لینک‌شده.

**پیاده‌سازی:**

- OpenAPI، GraphQL و endpointهای runtime در یک catalog نرمال شوند.
- undocumented route، method mismatch، version قدیمی، verbose error و content-type confusion بررسی شوند.
- GraphQL introspection، batching، depth/complexity، alias abuse و authorization روی resolverها با budget محدود تست شوند.
- method override، pagination boundary، mass-assignment signal و object identifierها به workflow نیازمند علامت‌گذاری شوند.
- پاسخ‌ها قبل از ذخیره redaction شوند؛ body کامل فقط در صورت نیاز و با سقف اندازه نگهداری شود.

### 6. Authentication و authorization workflows

**هدف:** اثبات ضعف‌هایی که با anonymous scan قابل نتیجه‌گیری نیستند.

**پیاده‌سازی:**

1. مدل `test_identities` با credential reference امن و secret manager تعریف شود؛ secret خام داخل DB یا report نرود.
2. workflowهای login، logout، reset، MFA، magic link و role matrix declarative شوند.
3. برای هر identity یک browser context جدا ساخته شود.
4. anonymous، same-user و cross-user responseها از نظر status، body shape، ownership و side effect مقایسه شوند.
5. IDOR/BOLA، vertical/horizontal privilege escalation، session fixation و logout invalidation فقط با evidence چندحسابی verified شوند.
6. workflowها باید disposable و قابل cleanup باشند؛ اجرای destructive action پیش‌فرض ممنوع باشد.

### 7. Upload، storage و privacy

**هدف:** پوشش خطاهای رایج deployment و application data handling.

**پیاده‌سازی:**

- form و API upload از surface graph استخراج شوند.
- فایل‌های harmless با MIME و extensionهای کنترل‌شده upload شوند.
- public object URL، predictable key، content sniffing، SVG/HTML rendering و حذف‌نشدن فایل بررسی شود.
- PII، token، referrer leakage، analytics destination و cache شدن response خصوصی inventory شوند.
- داده آزمایشی synthetic باشد و cleanup در `finally` تضمین شود.

### 8. Rate limit و abuse behavior

**هدف:** تشخیص دفاع‌های ضعیف بدون ایجاد فشار مخرب.

**پیاده‌سازی:**

- probeهای کم‌تعداد و budgetدار برای login، reset، API mutation و search تعریف شوند.
- status، delay، `Retry-After` و تغییر response بین درخواست‌ها ثبت شود.
- account lockout، replay و duplicate action با workflow idempotent بررسی شوند.
- race condition و payment abuse فقط به‌عنوان workflow اختصاصی و با target آزمایشی اجرا شوند.

### 9. Reporting و triage

**هدف:** تبدیل خروجی فنی به تصمیم قابل‌فهم.

**پیاده‌سازی:**

- صفحه report بر اساس severity، confidence، category و affected surface فیلتر شود.
- هر finding بخش‌های `What happened`، `Why it matters`، `Evidence`، `How to reproduce safely` و `How to fix` داشته باشد.
- coverage باید تعداد checkهای اجراشده، skippedها و prerequisiteهای مفقود را نشان دهد.
- findingهای تکراری با fingerprint پایدار merge شوند.
- export به JSON، HTML و در آینده SARIF اضافه شود.
- policy gate برای CI بر اساس verified severity و regression تعریف شود.

### 10. Frontend محصولی

**هدف:** تبدیل داشبورد فعلی به flow قابل استفاده برای تیم توسعه.

**پیاده‌سازی:**

- onboarding با ساخت workspace/project/target شروع شود.
- New Audit به جای path فایل، workflow و credential reference امن دریافت کند.
- صفحه Run زنده، stageها، progress، log خلاصه، cancel و retry را نشان دهد.
- صفحه Findings امکان triage، assign، suppress با دلیل، status و فیلتر داشته باشد.
- صفحه Attack Surface مسیرها، APIها، scriptها، subdomainها و evidence را به شکل قابل کاوش نشان دهد.
- report و baseline diff برای share کردن با تیم توسعه permalink داشته باشند.
- حالت loading، empty، failed و partial result برای همه صفحه‌ها طراحی شود.

### 11. Security و production hardening

- authentication و workspace authorization قبل از deploy عمومی اجباری است.
- SSRF scope، DNS rebinding، redirect validation، private network blocking و request budget در یک policy مرکزی enforce شوند.
- credentialها در secret manager یا encrypted reference نگهداری شوند.
- audit log برای شروع scan، تغییر policy، مشاهده evidence و export report ثبت شود.
- rate limit و resource limit روی API اعمال شود.
- Docker/CI browser image version pin شود تا شکست نصب وابستگی external باعث skip شدن تست‌ها نشود.

## ترتیب اجرای پیشنهادی

### Milestone 1 — Vertical slice

- یک target
- یک audit run پایدار
- stage progress
- discovery و checkهای فعلی
- findings با evidence، severity و confidence
- report قابل مشاهده در UI

### Milestone 2 — Surface و browser depth

- DNS/deployment discovery
- client artifact audit
- browser runtime evidence
- privacy و storage checks

### Milestone 3 — API و identity workflows

- OpenAPI/GraphQL catalog
- test identities
- authorization matrix
- IDOR/BOLA و session workflows

### Milestone 4 — Production control plane

- Postgres
- queue/worker
- SSE/WebSocket events
- authentication/workspaces
- secret manager
- deployment و observability

### Milestone 5 — CI و continuous audit

- baseline policy gates
- SARIF
- webhook/PR integration
- scheduled re-scan
- regression triage و notification

## Definition of Done برای هر check

هر check جدید فقط وقتی complete است که:

1. scope و safety rule داشته باشد.
2. check_id و fingerprint پایدار داشته باشد.
3. evidence redacted و bounded تولید کند.
4. verified، exposure و skipped را از هم جدا کند.
5. برای مثبت، منفی و prerequisite مفقود تست داشته باشد.
6. در report، coverage و UI نمایش داده شود.
7. cleanup و budget آن مشخص باشد.

## اولویت فوری

اولین کار اجرایی باید ساخت **Milestone 1** باشد. تا وقتی یک vertical slice پایدار با stage progress، finding evidence و report قابل‌فهم نداریم، اضافه‌کردن checkهای بیشتر فقط پیچیدگی را زیاد می‌کند و شکاف بین موتور scanner و محصول وب را بیشتر خواهد کرد.
