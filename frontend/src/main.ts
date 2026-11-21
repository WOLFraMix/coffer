import { Service } from '../bindings/github.com/WOLFraMix/coffer/internal/app';

const $create = document.getElementById('create')!;
const $unlock = document.getElementById('unlock')!;
const $app = document.getElementById('app')!;
const $list = document.getElementById('list')!;
const $err = document.getElementById('err')!;

function showError(msg: string) { $err.textContent = msg; }

// Отрисовка списка кодов. Вызывается раз в секунду таймером.
// Пока аккаунтов мало, полная перерисовка дешевле диффинга —
// оптимизируем, только если станет заметно тормозить.
async function refresh() {
    try {
        const codes = await Service.Codes();
        $list.innerHTML = '';
        for (const c of codes) {
            const row = document.createElement('div');
            row.className = 'row';
            row.innerHTML = `
        <div class="meta">
          <span class="issuer">${escapeHtml(c.issuer || '—')}</span>
          <span class="name">${escapeHtml(c.name)}</span>
        </div>
        <div class="right">
          <span class="code" title="Клик — скопировать">${c.code}</span>
          <span class="timer">${c.secondsLeft}с</span>
          <button class="del" title="Удалить">✕</button>
        </div>`;
            row.querySelector('.code')!.addEventListener('click', () => {
                navigator.clipboard.writeText(c.code);
                showError(`Скопировано: ${c.code}`);
            });
            row.querySelector('.del')!.addEventListener('click', async () => {
                try {
                    await Service.RemoveAccount(c.id);
                    await refresh();
                } catch (e: any) {
                    showError(e.message || String(e));
                }
            });
            $list.appendChild(row);
        }
    } catch (e: any) {
        // Сейф заблокирован извне (таймер) — покажем экран разблокировки.
        enterLockedState();
    }
}

// Минимальная защита от XSS: имя/сервис вводит сам пользователь.
function escapeHtml(s: string): string {
    return s.replace(/[&<>"']/g, (ch) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[ch]!));
}

// Таймер обновления. Заводим только при открытом сейфе.
let timer: number | undefined;
function startTicker() {
    if (timer === undefined) {
        timer = window.setInterval(refresh, 1000);
    }
}
function stopTicker() {
    if (timer !== undefined) {
        clearInterval(timer);
        timer = undefined;
    }
}

// Определяем, какой экран показывать: создание сейфа или ввод пароля.
// HasVault возвращает промис — обязательно await, иначе
// сравнивается сам промис, а не результат (тот всегда «истинный»).
async function enterLockedState() {
    stopTicker();
    $app.style.display = 'none';
    $list.innerHTML = '';

    const has = await Service.HasVault();
    $unlock.style.display = has ? 'flex' : 'none';
    $create.style.display = has ? 'none' : 'flex';
}

// --- Создание сейфа (первый запуск) ---
document.getElementById('btn-create')!.addEventListener('click', async () => {
    const p1 = (document.getElementById('new-password') as HTMLInputElement).value;
    const p2 = (document.getElementById('new-password2') as HTMLInputElement).value;
    if (p1 !== p2) { showError('Пароли не совпадают'); return; }
    try {
        await Service.CreateVault(p1);
        showError('');
        $create.style.display = 'none';
        $app.style.display = 'block';
        startTicker();
        refresh();
    } catch (e: any) {
        showError(e.message || String(e));
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
        refresh();
    } catch (e: any) {
        // ErrWrongPassword приходит как ошибка биндинга — показываем текст.
        showError('Неверный пароль');
    }
});

// --- Добавление аккаунта ---
document.getElementById('add')!.addEventListener('submit', async (e) => {
    e.preventDefault();
    const issuer = (document.getElementById('f-issuer') as HTMLInputElement).value;
    const name = (document.getElementById('f-name') as HTMLInputElement).value;
    const secret = (document.getElementById('f-secret') as HTMLInputElement).value;
    try {
        await Service.AddAccount(issuer, name, secret);
        (document.getElementById('f-secret') as HTMLInputElement).value = '';
        showError('');
        refresh();
    } catch (err: any) {
        showError(err.message || String(err));
    }
});

// --- Старт: какой экран показывать ---
enterLockedState();
