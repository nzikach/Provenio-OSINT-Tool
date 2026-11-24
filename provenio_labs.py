# -*- coding: utf-8 -*-
"""
Provenio — XSS-лаборатория: 14 намеренно уязвимых учебных «сайтов» с уровнями сложности.

Изоляция:
* лабы работают на ОТДЕЛЬНОМ локальном сервере (127.0.0.1, свой случайный порт = другой origin),
  в интерфейсе открываются в iframe с sandbox (без allow-same-origin): код из лабы не может
  обратиться ни к Provenio, ни к его токенам, ни к вашим данным;
* сервер лаб ничего не хранит, кроме комментариев учебной гостевой книги и черновика exploit-сервера.

Как засчитывается решение: в каждую страницу-«жертву» встроен перехватчик alert/confirm/prompt/print.
Если ваш payload вызвал одну из них в контексте сайта, перехватчик сообщает Provenio секретный
ключ, известный только страницам-жертвам (exploit-сервер его не видит — подделать решение нельзя).
"""
import html
import json
import re
import secrets
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = secrets.token_hex(12)
LEVELS = {1: "Новичок", 2: "Ученик", 3: "Практик", 4: "Эксперт", 5: "Безумие"}
STATE = {"comments": [], "exploit": {}}
LOCK = threading.Lock()
SERVER = {"port": None}

esc = html.escape


def esc_lt(s):
    """Экранирует только < > & — кавычки остаются (типичная ошибка)."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ======================================================================= оформление «сайтов»
SITE_CSS = """
*{box-sizing:border-box}body{margin:0;font:15px/1.55 system-ui,"Segoe UI",sans-serif;background:#f3f4fa;color:#1d1b2b}
.top{background:#fff;border-bottom:1px solid #e3e3ef;padding:13px 22px;display:flex;align-items:center;gap:12px}
.logo{font-weight:800;font-size:17px;color:var(--c)}.logo i{font-style:normal;display:inline-grid;place-items:center;width:28px;height:28px;
border-radius:8px;background:var(--c);color:#fff;margin-right:8px;font-size:14px}.nav{margin-left:auto;display:flex;gap:16px;font-size:13px;color:#6b6880}
main{max-width:780px;margin:22px auto;padding:0 18px}.box{background:#fff;border:1px solid #e3e3ef;border-radius:14px;padding:18px 20px;margin-bottom:14px;
box-shadow:0 2px 10px rgba(30,20,80,.05)}h2{margin:0 0 10px;font-size:19px}.mu{color:#7a768f;font-size:13px}
input,textarea{font:inherit;padding:10px 12px;border:1px solid #d6d5e4;border-radius:10px;width:100%;background:#fbfbfe}
textarea{min-height:80px}form{display:flex;gap:8px;flex-wrap:wrap}form.col{flex-direction:column}
button{font:600 14px inherit;padding:10px 16px;border:0;border-radius:10px;background:var(--c);color:#fff;cursor:pointer}
a{color:var(--c)}.c{border-top:1px solid #eee;padding:10px 0}.c b{color:var(--c)}.warn{background:#fff4f4;border-color:#f5c2c2;color:#9b1c1c}
code{background:#f0eff8;padding:1px 6px;border-radius:6px}
@keyframes pulse{from{opacity:.85}to{opacity:1}}.logo i{animation:pulse 2s infinite alternate}
"""


def hook(lab_id, nonce=None):
    n = f' nonce="{nonce}"' if nonce else ""
    return (f'<script{n}>(function(){{var K="{SECRET}",L={lab_id};function s(m){{m.provenioLab=L;m.k=K;try{{top.postMessage(m,"*")}}catch(e){{}}}}'
            '["alert","confirm","prompt","print"].forEach(function(f){window[f]=function(a){s({fn:f,arg:String(a===undefined?"":a).slice(0,120)})}});'
            'function nv(){s({nav:location.pathname+location.search+location.hash})}addEventListener("load",nv);addEventListener("hashchange",nv)})()</script>')


def site(lab, body, head="", nonce=None):
    return (f'<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>{lab["brand"]}</title>{hook(lab["id"], nonce)}'
            f'<style{" nonce=" + chr(34) + nonce + chr(34) if nonce else ""}>:root{{--c:{lab["color"]}}}{SITE_CSS}</style>{head}</head><body>'
            f'<div class="top"><span class="logo"><i>{lab["icon"]}</i>{lab["brand"]}</span><span class="nav">{lab.get("nav", "Главная · Помощь")}</span></div>'
            f'<main>{body}</main></body></html>')


def search_form(name, value, label="Найти", ph="Поиск…"):
    return (f'<form><input name="{name}" placeholder="{ph}" value="{esc(value)}" style="flex:1">'
            f'<button>{label}</button></form>')


# ======================================================================= уязвимые «сайты»
def l1(lab, rq):
    q = rq.q("q")
    res = f'<div class="box"><h2>Результаты по запросу: {q}</h2><p class="mu">Ничего не найдено. Попробуйте другой запрос.</p></div>' if q else ""
    return site(lab, f'<div class="box">{search_form("q", q)}</div>{res}')


def l2(lab, rq):
    if rq.method == "POST":
        name, text = rq.f("name")[:40] or "Аноним", rq.f("text")[:2000]
        with LOCK:
            STATE["comments"].append((name, text))
            del STATE["comments"][:-30]
        return 303, {"Location": "/lab/2/"}, ""
    cs = "".join(f'<div class="c"><b>{esc(n)}</b><div>{t}</div></div>' for n, t in STATE["comments"]) or '<p class="mu">Пока пусто — будьте первым!</p>'
    return site(lab, '<div class="box"><h2>Гостевая книга кибер-кафе</h2>'
                     '<form method="post" class="col"><input name="name" placeholder="Ваше имя">'
                     '<textarea name="text" placeholder="Сообщение (можно с <b>форматированием</b>)"></textarea><button>Оставить отзыв</button></form></div>'
                     f'<div class="box">{cs}</div>')


def l3(lab, rq):
    q = rq.q("q")
    return site(lab, f'<div class="box"><form><input name="q" placeholder="Найти товар" value="{esc_lt(q)}" style="flex:1"><button>Найти</button></form>'
                     f'<p class="mu">Вы искали: {esc(q) or "—"}</p></div>')


def l4(lab, rq):
    return site(lab, '<div class="box"><h2 id="sec"></h2><p class="mu">Документация загружается по разделам: '
                     '<a href="#Введение">Введение</a> · <a href="#API">API</a> · <a href="#FAQ">FAQ</a></p></div>'
                     '<script>function show(){var s=decodeURIComponent(location.hash.slice(1)||"Главная");'
                     'document.getElementById("sec").innerHTML="Раздел: <u>"+s+"</u>"}addEventListener("hashchange",show);show()</script>')


def l5(lab, rq):
    q = rq.q("q")
    v = q.replace("'", "\\'").replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ").replace("\r", " ")
    return site(lab, f'<div class="box">{search_form("q", q, "Искать по счетам")}<p id="o" class="mu"></p></div>'
                     f"<script>var query = '{v}';\ndocument.getElementById('o').textContent = 'Ищем операции: ' + query;</script>")


def l6(lab, rq):
    u = rq.q("site")
    clean = re.sub(r"javascript:", "", u, flags=re.I)      # «защита» — один проход
    card = (f'<div class="box"><h2>Профиль: neo_user</h2><p>Мой сайт: <a href="{esc(clean)}">{esc(clean)}</a></p>'
            '<p class="mu">Ссылки на javascript: запрещены нашим фильтром ✔</p></div>') if u else ""
    return site(lab, f'<div class="box"><form><input name="site" placeholder="https://ваш-сайт.ru" value="{esc(u)}" style="flex:1">'
                     f'<button>Сохранить</button></form></div>{card}')


def l7(lab, rq):
    q = rq.q("user") or "guest"
    state = json.dumps({"user": q, "theme": "dark", "plan": "pro"}, ensure_ascii=False)
    return site(lab, f'<div class="box">{search_form("user", q, "Войти как", "Имя пользователя")}<h2 id="hi"></h2></div>'
                     f'<script>window.__STATE__ = {state};</script>'
                     '<script>document.getElementById("hi").textContent="Привет, "+__STATE__.user+"!"</script>')


def l8(lab, rq):
    q = rq.q("q")
    e = esc(q, quote=True)
    return site(lab, f'<div class="box">{search_form("q", q, "Создать ссылку", "Что отслеживаем?")}</div>'
                     + (f'<div class="box"><p>Ссылка для «{e}» готова.</p><button onclick="track(\'{e}\')">📤 Поделиться</button></div>'
                        '<script>function track(x){console.log("track",x)}</script>' if q else ""))


WAF_RULES = [r"<script", r"javascript:", r"alert", r"onerror", r"onload", r"onclick", r"onmouseover", r"onfocus",
             r"onmouseenter", r"onanimationstart", r"<iframe", r"eval", r"srcdoc", r"onbegin"]


def l9(lab, rq):
    q = rq.q("q")
    for i, rule in enumerate(WAF_RULES, 1):
        if re.search(rule, q, re.I):
            return 403, {}, site(lab, f'<div class="box warn"><h2>🛡 NeoWAF: запрос заблокирован</h2>'
                                      f'<p>Сработало правило <code>#{i:02d}</code>. Инцидент записан.</p><a href="/lab/9/">Назад</a></div>')
    res = f'<div class="box"><h2>Новости по теме: {q}</h2><p class="mu">Под защитой NeoWAF Enterprise.</p></div>' if q else ""
    return site(lab, f'<div class="box">{search_form("q", q)}</div>{res}')


def sanitize10(s):
    prev = None
    while prev != s:
        prev = s
        s = re.sub(r"<script\b[^>]*>.*?</script\s*>", "", s, flags=re.I | re.S)
        s = re.sub(r"</?script[^>]*>", "", s, flags=re.I)
    s = re.sub(r"""\son\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""", "", s, flags=re.I)
    return re.sub(r"javascript:", "", s, flags=re.I)


def l10(lab, rq):
    t = rq.q("text")
    prev = f'<div class="box"><p class="mu">Предпросмотр (очищено фильтром SafeHTML 2.0):</p>{sanitize10(t)}</div>' if t else ""
    return site(lab, '<div class="box"><h2>Новый пост</h2><form class="col"><textarea name="text" placeholder="Текст поста, HTML разрешён">'
                     f'{esc(t)}</textarea><button>Предпросмотр</button></form></div>{prev}')


def l11(lab, rq):
    return site(lab, '<div class="box"><h2>Поддержка 24/7</h2><div id="banner" class="mu">Загрузка объявления…</div>'
                     '<p>Чат откроется здесь. Партнёрские сайты могут встраивать нас и присылать объявления.</p></div>'
                     '<script>addEventListener("message",function(e){/* TODO: проверить e.origin */'
                     'if(typeof e.data==="string")document.getElementById("banner").innerHTML=e.data})</script>')


def l12(lab, rq):
    name = rq.q("name") or "гость"
    return site(lab, f'<div class="box">{search_form("name", name, "Представиться", "Ваше имя")}</div>'
                     f'<div class="box" id="app"><h2>Привет, {esc(name)}!</h2><p>Сегодня {{{{ today }}}}, длина имени — {{{{ len("{esc(name)}") }}}}.</p></div>'
                     r'''<script>(function(){
var BL=/alert|confirm|prompt|print|window|document|eval|Function|constructor|globalThis|self|top|parent|frames|opener|location|import|setTimeout|setInterval|fetch|XMLHttpRequest|Reflect/;
var scope={today:new Date().toLocaleDateString("ru"),upper:function(s){return String(s).toUpperCase()},len:function(s){return String(s).length}};
var px=new Proxy(scope,{has:function(){return true},get:function(t,k){return k===Symbol.unscopables?undefined:t[k]}});
function un(s){return s.replace(/&lt;/g,"<").replace(/&gt;/g,">").replace(/&quot;/g,'"').replace(/&#x27;/g,"'").replace(/&amp;/g,"&")}
function he(s){return String(s).replace(/[&<>"']/g,function(c){return"&#"+c.charCodeAt(0)+";"})}
var el=document.getElementById("app");
el.innerHTML=el.innerHTML.replace(/\{\{([\s\S]+?)\}\}/g,function(m,ex){ex=un(ex);if(BL.test(ex))return"⛔";
 try{return he(new Function("s","with(s){return ("+ex+")}")(px))}catch(e){return"⚠"}});
})()</script>''')


def l13(lab, rq):
    q = rq.q("id")
    nonce = secrets.token_urlsafe(12)
    origin = f"http://{rq.host}"
    csp = (f"default-src 'none'; script-src {origin} 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
           f"img-src {origin} data:; base-uri 'none'; form-action {origin}")
    res = f'<div class="box warn">Профиль не найден: {q}</div>' if q else ""
    body = (f'<div class="box">{search_form("id", q, "Открыть профиль", "ID пользователя")}<h2 id="u">…</h2></div>{res}'
            f'<script nonce="{nonce}">function renderUser(u){{document.getElementById("u").textContent="Вошли как "+u.name}}</script>'
            f'<script nonce="{nonce}" src="/lab/13/api/user?callback=renderUser"></script>')
    return 200, {"Content-Security-Policy": csp}, site(lab, body, nonce=nonce)


def l13_api(lab, rq):
    cb = rq.q("callback") or "callback"
    if not re.fullmatch(r"[\w.]{1,40}", cb):
        cb = "callback"
    return 200, {"Content-Type": "application/javascript; charset=utf-8"}, f'{cb}({{"name":"guest","id":1}})'


def sanitize14(s):
    """«Строгий» allowlist: теги a b i p img, атрибуты id name href title src alt; javascript: в ссылках запрещён."""
    from html.parser import HTMLParser
    out = []
    tags = {"a", "b", "i", "p", "img", "br"}
    attrs_ok = {"id", "name", "href", "title", "src", "alt"}

    class P(HTMLParser):
        def handle_starttag(self, tag, attrs):
            if tag not in tags:
                return
            parts = []
            for k, v in attrs:
                v = v or ""
                if k not in attrs_ok or (k in ("href", "src") and re.match(r"\s*javascript:", v, re.I)):
                    continue
                parts.append(f' {k}="{esc(v)}"')
            out.append(f"<{tag}{''.join(parts)}>")

        def handle_endtag(self, tag):
            if tag in tags and tag not in ("img", "br"):
                out.append(f"</{tag}>")

        def handle_data(self, data):
            out.append(esc(data))
    P(convert_charrefs=True).feed(s)
    return "".join(out)


def l14(lab, rq):
    bio = rq.q("bio")
    shown = sanitize14(bio) if bio else '<i class="mu">Пользователь пока ничего не рассказал о себе.</i>'
    return site(lab, '<div class="box"><h2>О себе</h2><form class="col"><textarea name="bio" placeholder="Расскажите о себе (HTML: a, b, i, p, img)">'
                     f'{esc(bio)}</textarea><button>Сохранить</button></form></div><div class="box">{shown}</div>'
                     '<script>var cfg = window.siteConfig || {theme: "light"};'
                     'if (cfg.analytics) { var s = document.createElement("script"); s.src = cfg.analytics; document.body.appendChild(s); }</script>')


# ======================================================================= каталог лаб
LABS = [
    dict(id=1, level=1, fn=l1, brand="NeoSearch", icon="⌕", color="#2563eb", ctx="HTML · отражённая",
         title="Поиск без фильтров",
         story="Стартап NeoSearch выкатил поиск за выходные. Запрос выводится в заголовке результатов «как есть».",
         hints=["Посмотрите, куда попадает параметр q: откройте ?q=<b>тест</b>.",
                "Если ваш HTML отрисовался — сайт не экранирует ввод.",
                "Самый прямой путь — тег <script> с вызовом alert()."],
         solution="/lab/1/?q=<script>alert(1)</script>",
         fix="Экранируйте вывод по контексту: html.escape(q) (или авто-экранирование шаблонизатора). Плюс Content-Security-Policy без 'unsafe-inline'."),
    dict(id=2, level=1, fn=l2, brand="CyberCafe", icon="☕", color="#ea580c", ctx="HTML · хранимая",
         title="Гостевая книга",
         story="Кибер-кафе разрешило «форматирование» в отзывах. Имя экранируется, а текст отзыва — нет. Отзыв видят все посетители.",
         hints=["Хранимая XSS срабатывает у каждого, кто открывает страницу — включая вас после отправки.",
                "Поле имени экранируется. Атакуйте поле сообщения.",
                "<script> работает, но попробуйте и без него: <img src=x onerror=…>."],
         solution="Сообщение: <img src=x onerror=alert(1)>",
         fix="Не храните и не выводите «сырой» HTML от пользователя. Если форматирование нужно — Markdown или HTML-санитайзер с allowlist (DOMPurify / bleach), плюс CSP."),
    dict(id=3, level=2, fn=l3, brand="ShopX", icon="🛒", color="#16a34a", ctx="атрибут value",
         title="Кавычка, которую забыли",
         story="ShopX экранирует < и >, поэтому новый тег не вставить. Но ввод попадает внутрь value=\"…\" поля поиска.",
         hints=["Посмотрите исходник: ваш ввод внутри value=\"…\". Какие символы НЕ экранируются?",
                "Двойная кавычка закрывает атрибут — можно дописать свои атрибуты к <input>.",
                "Самое простое — onmouseover и навести курсор на поле. Без участия пользователя: style=\"animation-name:pulse\" + onanimationstart — анимация pulse на сайте уже объявлена (autofocus в чужом iframe браузер блокирует)."],
         solution='/lab/3/?q=" onmouseover="alert(1) → навести курсор на поле. Без клика: /lab/3/?q=" style="animation-name:pulse" onanimationstart="alert(1)',
         fix="В атрибутах экранируйте и кавычки: html.escape(q, quote=True) → &quot;. Всегда берите значения атрибутов в кавычки."),
    dict(id=4, level=2, fn=l4, brand="DocsHub", icon="📘", color="#0891b2", ctx="DOM · location.hash",
         title="Раздел из адресной строки",
         story="Документация DocsHub рисует заголовок раздела из части URL после #. Сервер её даже не видит — уязвим сам JavaScript.",
         hints=["Фрагмент после # не уходит на сервер: смотрите код страницы, а не ответ сервера.",
                "Заголовок собирается через innerHTML — HTML из # будет разобран.",
                "<script> через innerHTML не выполнится. Нужен тег с обработчиком: <img src=x onerror=…>."],
         solution="/lab/4/#<img src=x onerror=alert(1)>",
         fix="Не используйте innerHTML для данных: textContent / createTextNode. Для DOM-XSS — Trusted Types (require-trusted-types-for 'script')."),
    dict(id=5, level=3, fn=l5, brand="BankNova", icon="🏦", color="#7c3aed", ctx="строка JavaScript",
         title="Экранированная кавычка",
         story="BankNova вставляет запрос в var query = '…'. Разработчик экранирует апостроф как \\' и угловые скобки — закрыть </script> не выйдет.",
         hints=["Апостроф превращается в \\'. А что происходит с самим обратным слешем?",
                "Если отправить \\' — сервер сделает \\\\' : первый слеш экранирует второй, и апостроф снова закрывает строку.",
                "После закрытия строки: ;alert(1)// — двойной слеш закомментирует хвост."],
         solution="/lab/5/?q=\\';alert(1)//",
         fix="Не собирайте JS из строк. Передавайте данные через JSON в data-атрибуте или json.dumps с экранированием </ и \\. Обратный слеш нужно экранировать первым."),
    dict(id=6, level=3, fn=l6, brand="LinkTree", icon="🔗", color="#db2777", ctx="href · фильтр схем",
         title="Фильтр javascript:",
         story="Профиль позволяет указать ссылку на свой сайт. Кавычки экранируются, а «javascript:» вырезается фильтром.",
         hints=["Фильтр удаляет подстроку один раз — он не повторяет проверку после удаления.",
                "Что останется от «javajavascript:script:» после удаления внутреннего вхождения?",
                "Сохраните такую ссылку и кликните по ней."],
         solution="/lab/6/?site=javajavascript:script:alert(1) → клик по ссылке",
         fix="Не вычищайте опасное — разрешайте только известное: urllib.parse.urlsplit(u).scheme in ('http','https'), иначе отклонить."),
    dict(id=7, level=3, fn=l7, brand="AppState", icon="⚙", color="#0d9488", ctx="JSON внутри <script>",
         title="Состояние в скрипте",
         story="SPA кладёт начальное состояние прямо в страницу: window.__STATE__ = {…}. JSON сериализуется корректно — кавычки экранированы.",
         hints=["Строку JSON внутри не сломать: json.dumps экранирует кавычки.",
                "Но HTML-парсер ищет конец скрипта раньше, чем запускается JavaScript.",
                "</script> внутри строки закроет тег — дальше можно открыть свой."],
         solution="/lab/7/?user=</script><script>alert(1)</script>",
         fix="При встраивании JSON в <script> экранируйте <, > и & как \\u003c, \\u003e, \\u0026 (или отдавайте данные через <script type=application/json> + textContent)."),
    dict(id=8, level=4, fn=l8, brand="TrackLink", icon="📤", color="#4f46e5", ctx="JS внутри onclick",
         title="Правильное экранирование не там",
         story="TrackLink экранирует всё по правилам HTML: < > \" ' &. Ввод попадает в onclick=\"track('…')\". Что может пойти не так?",
         hints=["Апостроф превращается в &#x27;. А что браузер делает с сущностями внутри значения атрибута — ДО запуска JS?",
                "Атрибут сначала декодируется (&#x27; → '), потом его содержимое выполняется как JavaScript.",
                "Закройте строку и вызов: ');alert(1);// — и нажмите «Поделиться»."],
         solution="/lab/8/?q=');alert(1);// → кнопка «Поделиться»",
         fix="Не вставляйте данные в обработчики событий. Повесьте обработчик через addEventListener, а данные передайте в data-атрибуте. В JS-контексте нужно JS-экранирование, а не HTML."),
    dict(id=9, level=4, fn=l9, brand="NeoWAF Portal", icon="🛡", color="#dc2626", ctx="обход WAF",
         title="Чёрный список NeoWAF",
         story="Портал защищён «корпоративным» WAF: блокирует <script, javascript:, alert, eval и популярные обработчики событий. Отражение в HTML — без экранирования.",
         hints=["Чёрный список никогда не полный: событий в HTML больше сотни.",
                "Есть события, срабатывающие без участия пользователя: ontoggle у <details open>, onbegin у SVG-анимаций (последний заблокирован).",
                "alert заблокирован — подойдёт print() или confirm()."],
         solution="/lab/9/?q=<details open ontoggle=print()>",
         fix="WAF — не защита от XSS. Экранируйте вывод; WAF и CSP — только дополнительные слои."),
    dict(id=10, level=4, fn=l10, brand="SafeHTML Blog", icon="✎", color="#ca8a04", ctx="обход санитайзера",
         title="SafeHTML 2.0",
         story="Блог разрешает HTML в постах и чистит его регулярками: рекурсивно вырезает <script>, удаляет атрибуты on…=, убирает javascript:.",
         hints=["Регулярка атрибутов ищет пробельный символ перед on…",
                "В HTML атрибуты можно отделять не только пробелом: например, «/».",
                "Попробуйте SVG: <svg/onload=…>."],
         solution="/lab/10/?text=<svg/onload=alert(1)>",
         fix="Санитайзер на регулярках не работает — HTML разбирается иначе, чем вы думаете. Используйте парсер и allowlist (DOMPurify, bleach/nh3) и выводите результат того же парсера."),
    dict(id=11, level=4, fn=l11, brand="HelpChat", icon="💬", color="#2563eb", ctx="postMessage · exploit-сервер",
         title="Сообщения без проверки", exploit=True,
         story="Виджет чата принимает «объявления» от партнёров через postMessage и вставляет их в страницу. Проверку origin так и не дописали. Атакуйте через свой exploit-сервер.",
         hints=["Сама страница ничего не берёт из URL. Данные приходят только через window.postMessage.",
                "На exploit-сервере встройте сайт в <iframe> и отправьте ему сообщение, когда он загрузится.",
                "<iframe src=\"/lab/11/\" onload=\"this.contentWindow.postMessage('<img src=x onerror=print()>','*')\"></iframe>"],
         solution="Exploit-сервер: <iframe src=\"/lab/11/\" onload=\"this.contentWindow.postMessage('<img src=x onerror=print()>','*')\"></iframe>",
         fix="Всегда проверяйте e.origin по списку разрешённых и не вставляйте e.data через innerHTML. Плюс заголовок frame-ancestors, чтобы сайт нельзя было встроить."),
    dict(id=12, level=5, fn=l12, brand="HelloTemplate", icon="{}", color="#9333ea", ctx="шаблоны · побег из песочницы",
         title="Побег из песочницы шаблонов",
         story="Сервер честно экранирует имя. Но на клиенте работает мини-движок шаблонов: выражения {{ … }} вычисляются в «песочнице» с Proxy и чёрным списком слов (alert, window, constructor, Function, eval…).",
         hints=["Ваше экранированное имя всё равно попадает в текст, а движок ищет в тексте {{ … }}. Проверьте ?name={{7*7}}.",
                "Глобальные имена недоступны, но доступны функции из scope: upper, len. У любой функции есть конструктор — Function, а слово «constructor» можно собрать из частей.",
                "{{ upper['constr'+'uctor']('pri'+'nt()')() }}"],
         solution="/lab/12/?name={{ upper['constr'+'uctor']('pri'+'nt()')() }}",
         fix="Никогда не вычисляйте пользовательские выражения (new Function / eval), даже «в песочнице». Не смешивайте серверный вывод с клиентскими шаблонами: v-pre / ng-non-bindable, строгий CSP без 'unsafe-eval'."),
    dict(id=13, level=5, fn=l13, brand="SecureCorp", icon="🔒", color="#0f766e", ctx="обход CSP · JSONP",
         title="CSP: только свои скрипты",
         story="SecureCorp внедрил строгий Content-Security-Policy: скрипты только с собственного домена или с одноразовым nonce. Отражение ID в HTML никто не чинил — «CSP же защитит».",
         hints=["Инлайн-скрипты и обработчики событий CSP заблокирует. Нужен скрипт с разрешённого источника — с этого же сайта.",
                "Посмотрите, какие скрипты сайт загружает сам. Один из них — JSONP с параметром callback.",
                "<script src=\"/lab/13/api/user?callback=print\"></script>"],
         solution="/lab/13/?id=<script src=\"/lab/13/api/user?callback=print\"></script>",
         fix="Уберите JSONP и другие эндпоинты, которые отражают ввод как JS. CSP на nonce + 'strict-dynamic' без доверия к хосту; и всё равно экранируйте вывод — CSP лишь второй слой."),
    dict(id=14, level=5, fn=l14, brand="ProfileHub", icon="👤", color="#be123c", ctx="DOM clobbering",
         title="Затирание DOM",
         story="«О себе» проходит через настоящий парсер с allowlist: только a, b, i, p, img и атрибуты id, name, href, title, src, alt; javascript: в ссылках запрещён. Обработчиков нет. Но скрипт сайта читает window.siteConfig…",
         hints=["Элементы с id становятся свойствами window. Это называется DOM clobbering.",
                "Скрипт берёт cfg.analytics и подключает его как src скрипта. Два элемента с одним id дают HTMLCollection, а в ней элемент можно достать по name.",
                "Ссылка превращается в строку через href. Схема data: фильтром не запрещена: <a id=siteConfig><a id=siteConfig name=analytics href=\"data:,print()\">"],
         solution="/lab/14/?bio=<a id=siteConfig><a id=siteConfig name=analytics href=\"data:,print()\">",
         fix="Не полагайтесь на глобальные переменные (window.x || …) — объявляйте их явно. Санитайзер должен запрещать id/name (DOMPurify SANITIZE_DOM) и разрешать только http/https в ссылках."),
]
BY_ID = {lab["id"]: lab for lab in LABS}
PUBLIC_KEYS = ("id", "level", "brand", "icon", "color", "ctx", "title", "story", "hints")


def catalog():
    out = []
    for lab in LABS:
        d = {k: lab[k] for k in PUBLIC_KEYS}
        d["level_name"] = LEVELS[lab["level"]]
        d["exploit"] = bool(lab.get("exploit"))
        out.append(d)
    return out


def reveal(lab_id):
    lab = BY_ID[int(lab_id)]
    return {"solution": lab["solution"], "fix": lab["fix"]}


def reset(lab_id):
    with LOCK:
        if int(lab_id) == 2:
            STATE["comments"].clear()
        STATE["exploit"].pop(int(lab_id), None)


def set_exploit(lab_id, body):
    if not BY_ID.get(int(lab_id), {}).get("exploit"):
        raise ValueError("У этой лабы нет exploit-сервера")
    with LOCK:
        STATE["exploit"][int(lab_id)] = str(body)[:20000]


# ======================================================================= сервер лаб
class Req:
    def __init__(self, method, query, form, host):
        self.method, self._q, self._f, self.host = method, query, form, host

    def q(self, k):
        return (self._q.get(k) or [""])[0]

    def f(self, k):
        return (self._f.get(k) or [""])[0]


class LabHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, headers=None):
        headers = dict(headers or {})
        ctype = headers.pop("Content-Type", "text/html; charset=utf-8")
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-XSS-Protection", "0")
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def route(self, method):
        u = urllib.parse.urlsplit(self.path)
        host = self.headers.get("Host", "")
        if host.split(":")[0] not in ("127.0.0.1", "localhost"):
            return self.send(403, "forbidden")
        q = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        form = {}
        if method == "POST":
            n = min(int(self.headers.get("Content-Length") or 0), 64 * 1024)
            form = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"), keep_blank_values=True)
        m = re.match(r"^/lab/(\d+)(/.*)?$", u.path)
        if m and int(m.group(1)) in BY_ID:
            lab, rest = BY_ID[int(m.group(1))], m.group(2) or "/"
            rq = Req(method, q, form, host)
            if lab["id"] == 13 and rest.startswith("/api/user"):
                r = l13_api(lab, rq)
            elif rest in ("/", ""):
                r = lab["fn"](lab, rq)
            else:
                return self.send(404, site(lab, '<div class="box"><h2>404</h2></div>'))
            if isinstance(r, str):
                r = (200, {}, r)
            return self.send(*r[:1], r[2], r[1])
        m = re.match(r"^/exploit/(\d+)$", u.path)
        if m:
            body = STATE["exploit"].get(int(m.group(1)), "<p>Exploit-сервер пуст: напишите HTML и нажмите «Доставить жертве».</p>")
            return self.send(200, "<!doctype html><meta charset=utf-8><title>exploit-server</title>"
                                  "<style>body{font:14px system-ui;background:#111;color:#ddd}iframe{width:100%;height:92vh;border:0}</style>" + body)
        return self.send(404, "not found", {"Content-Type": "text/plain; charset=utf-8"})

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")


def ensure_server():
    """Запускает сервер лаб (один раз) и возвращает его порт."""
    with LOCK:
        if SERVER["port"]:
            return SERVER["port"]
        srv = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        SERVER["port"] = srv.server_address[1]
        SERVER["srv"] = srv
        return SERVER["port"]
