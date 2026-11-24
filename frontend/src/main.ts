import { Service } from '../bindings/github.com/WOLFraMix/coffer/internal/app';

const $create = document.getElementById('create')!;
const $unlock = document.getElementById('unlock')!;
const $app = document.getElementById('app')!;
const $list = document.getElementById('list')!;
const $err = document.getElementById('err')!;

function errText(e: unknown): string {
    if (typeof e === 'string') return e;
    const any = e as { message?: string };
    return any?.message ?? String(e);
}
function showError(msg: string) { $err.textContent = msg; }

// --- Список кодов: кэш + клиентская фильтрация ---
let lastCodes: NonNullable<Awaited<ReturnType<typeof Service.Codes>>> = [];

async function refresh() {
    try {
        lastCodes = (await Service.Codes()) ?? [];
        renderList();
    } catch (e) {
        const msg = errText(e);
        if (msg.includes('locked')) enterLockedState();
        else showError(msg);
    }
}

// Поиск без обращения к бэкенду: фильтруем кэш по подстроке.
// Список всё равно перерисовывается каждую секунду — фильтр живёт там же.
const $search = document.getElementById('search') as HTMLInputElement;
$search.addEventListener('input', renderList);

function matchesQuery(c: { issuer: string; name: string }): boolean {
    const q = $search.value.trim().toLowerCase();
    if (!q) return true;
    return (c.issuer + ' ' + c.name).toLowerCase().includes(q);
}

function renderList() {
    $list.innerHTML = '';
    const visible = lastCodes.filter(matchesQuery);
    const q = $search.value.trim();
    if (q && visible.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'empty';
        empty.textContent = 'Ничего не найдено';
        $list.appendChild(empty);
        return;
    }
    for (const c of visible) {
        const row = document.createElement('div');
        row.className = 'row';
        row.innerHTML = `
      <div class="meta">
        <span class="issuer">${escapeHtml(c.issuer || '—')}</span>
        <span class="name">${escapeHtml(c.name)}</span>
      </div>
      <div class="right">
        <span class="code" title="Клик — скопировать">${c.code}</span>
        <span class="timer">${c.secondsLeft}</span>
        <button class="del" title="Удалить">✕</button>
      </div>
      <div class="bar"><i style="width:${(c.secondsLeft / 30) * 100}%"></i></div>`;
        row.querySelector('.code')!.addEventListener('click', () => {
            navigator.clipboard.writeText(c.code);
            showError(`Скопировано: ${c.code}`);
        });
        row.querySelector('.del')!.addEventListener('click', async () => {
            try {
                await Service.RemoveAccount(c.id);
                showError('');
                await refresh();
            } catch (e) {
                showError(errText(e));
            }
        });
        $list.appendChild(row);
    }
}

function escapeHtml(s: string): string {
    return s.replace(/[&<>"']/g, (ch) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[ch]!));
}

let timer: number | undefined;
function startTicker() {
    if (timer === undefined) timer = window.setInterval(refresh, 1000);
}
function stopTicker() {
    if (timer !== undefined) { clearInterval(timer); timer = undefined; }
}

// --- Активность: Touch не чаще раза в 10 секунд ---
let lastTouchSent = 0;
function touch() {
    const now = Date.now();
    if (now - lastTouchSent > 10_000) {
        lastTouchSent = now;
        Service.Touch();
    }
}
for (const ev of ['mousemove', 'keydown', 'pointerdown']) {
    document.addEventListener(ev, touch);
}

function enterLockedState() {
    stopTicker();
    $app.style.display = 'none';
    $list.innerHTML = '';
    Service.HasVault().then(has => {
        $unlock.style.display = has ? 'flex' : 'none';
        $create.style.display = has ? 'none' : 'flex';
    });
}

document.getElementById('password')!.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') (document.getElementById('btn-unlock') as HTMLButtonElement).click();
});

// --- Создание сейфа ---
document.getElementById('btn-create')!.addEventListener('click', async () => {
    const p1 = (document.getElementById('new-password') as HTMLInputElement).value;
    const p2 = (document.getElementById('new-password2') as HTMLInputElement).value;
    if (p1 !== p2) { showError('Пароли не совпадают'); return; }
    if (p1.length < 8) { showError('Минимум 8 символов'); return; }
    try {
        await Service.CreateVault(p1);
        (document.getElementById('new-password') as HTMLInputElement).value = '';
        (document.getElementById('new-password2') as HTMLInputElement).value = '';
        showError('');
        $create.style.display = 'none';
        $app.style.display = 'block';
        startTicker();
        await refresh();
    } catch (e) {
        showError(errText(e));
    }
});

// --- Разблокировка ---
document.getElementById('btn-unlock')!.addEventListener('click', async () => {
    const pwd = (document.getElementById('password') as HTMLInputElement).value;
    try {
        await Service.Unlock(pwd);
        showError('');
        $unlock.style.display = 'none';
        $app.style.display = 'block';
        startTicker();
        await refresh();
    } catch (e) {
        showError(errText(e));
    }
});

// --- Заблокировать ---
document.getElementById('btn-lock')!.addEventListener('click', async (e) => {
    e.preventDefault();
    await Service.Lock();
    enterLockedState();
});

// --- Сброс сейфа: двухшаговое подтверждение ---
let resetArmed: number | undefined;
document.getElementById('btn-reset')!.addEventListener('click', async (e) => {
    e.preventDefault();
    const btn = e.currentTarget as HTMLAnchorElement;
    if (resetArmed === undefined) {
        btn.textContent = 'Точно удалить? Все коды пропадут. Нажмите ещё раз';
        btn.classList.add('danger');
        resetArmed = window.setTimeout(disarmReset, 4000);
        return;
    }
    disarmReset();
    try {
        await Service.ResetVault();
        (document.getElementById('password') as HTMLInputElement).value = '';
        showError('');
        enterLockedState();
    } catch (err) {
        showError(errText(err));
    }
});
function disarmReset() {
    if (resetArmed !== undefined) { clearTimeout(resetArmed); resetArmed = undefined; }
    const btn = document.getElementById('btn-reset')!;
    btn.textContent = 'Забыли пароль? Сбросить сейф…';
    btn.classList.remove('danger');
}

// --- Валидация секрета (Base32: A-Z и 2-7, длина кратна 8) ---
function validateSecret(secret: string): string | null {
    const s = secret.replace(/\s+/g, '').toUpperCase();
    if (s.length === 0) return 'Введите секрет';
    if (!/^[A-Z2-7]+$/.test(s)) return 'Секрет: только латиница A–Z и цифры 2–7 (Base32)';
    if (s.length < 16) return 'Слишком короткий секрет (минимум 16 символов)';
    if (s.length % 8 !== 0) return 'Длина секрета должна быть кратна 8 (сейчас ' + s.length + ')';
    return null;
}

// --- Добавление аккаунта ---
document.getElementById('add')!.addEventListener('submit', async (e) => {
    e.preventDefault();
    const issuer = (document.getElementById('f-issuer') as HTMLInputElement).value.trim();
    const name = (document.getElementById('f-name') as HTMLInputElement).value.trim();
    const rawSecret = (document.getElementById('f-secret') as HTMLInputElement).value;
    const problem = validateSecret(rawSecret);
    if (problem) { showError(problem); return; }
    try {
        await Service.AddAccount(issuer, name, rawSecret);
        (document.getElementById('f-secret') as HTMLInputElement).value = '';
        showError('');
        refresh();
    } catch (err) {
        showError(errText(err));
    }
});

// --- Экспорт резервной копии ---
document.getElementById('btn-export')!.addEventListener('click', async () => {
    const pw = (document.getElementById('backup-password') as HTMLInputElement).value;
    if (pw.length < 8) { showError('Пароль копии — минимум 8 символов'); return; }
    try {
        const path = await Service.ExportBackup(pw);
        (document.getElementById('backup-password') as HTMLInputElement).value = '';
        showError(`Копия сохранена: ${path}`);
    } catch (e) {
        showError(errText(e));
    }
});

// --- Импорт резервной копии ---
document.getElementById('btn-import')!.addEventListener('click', async () => {
    const path = (document.getElementById('import-path') as HTMLInputElement).value.trim();
    const pw = (document.getElementById('import-password') as HTMLInputElement).value;
    if (!path) { showError('Укажите путь к файлу копии'); return; }
    try {
        const added = await Service.ImportBackup(path, pw);
        (document.getElementById('import-password') as HTMLInputElement).value = '';
        showError(added > 0 ? `Добавлено аккаунтов: ${added}` : 'Новых аккаунтов нет — всё уже есть в сейфе');
        await refresh();
    } catch (e) {
        showError(errText(e));
    }
});

enterLockedState();
