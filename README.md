# 🔐 Coffer

[![CI](https://img.shields.io/github/actions/workflow/status/WOLFraMix/coffer/ci.yml?branch=main&label=CI&style=flat-square)](https://github.com/WOLFraMix/coffer/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/WOLFraMix/coffer?include_prereleases&style=flat-square)](https://github.com/WOLFraMix/coffer/releases)
[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go&logoColor=white&style=flat-square)](https://go.dev)
[![Wails](https://img.shields.io/badge/Wails-v3-DF2667?style=flat-square)](https://wails.io)
[![License](https://img.shields.io/github/license/WOLFraMix/coffer?style=flat-square)](LICENSE)

Локальный аутентификатор 2FA: коды TOTP без облаков. Ваша копия — ваши ключи: секреты хранятся в шифрованном сейфе на вашем диске, ни один сервер ничего не знает.

## Возможности

- **TOTP-коды** (RFC 6238) с обратным отсчётом и прогресс-баром — как в Google Authenticator, но на рабочем столе
- **Шифрованный сейф** — AES-GCM, ключ выводится из мастер-пароля (PBKDF2), пароль нигде не хранится
- **Автоблокировка** по простою — сейф закрывается сам, если вы не трогали окно 5 минут
- **Системный трей** — коды всегда под рукой, окно закрывается в трей, а не насовсем
- **Резервные копии** — экспорт/импорт зашифрованного файла с отдельным паролем, импорт сливает данные, не затирая существующее
- **Поиск** по сервисам и аккаунтам
- **CLI** — `cofferctl create/open/reset` для диагностики и автоматизации

## Сборка

Требуется: Go 1.22+, Node.js 18+, [Wails CLI v3](https://v3.wails.io/).

```powershell
wails3 task build      # сборка GUI (bin/coffer.exe)
go build ./cmd/cofferctl  # сборка CLI
```

## Тесты

```powershell
go test ./... -count=1
```

## Структура проекта

```
main.go              — точка входа: окно, трей, меню
internal/
  vault/             — шифрованный сейф: формат COFF, соль, PBKDF2, AES-GCM
  otp/               — генерация TOTP-кодов
  app/               — сервисный слой между ядром и UI
  cmd/cofferctl/     — CLI: create/open/reset
frontend/
  src/main.ts        — логика UI
  index.html, style.css
```

## Формат сейфа

Файл `coffer.cof` (расположение: `%APPDATA%/Coffer/`):

```
magic "COFF" | version | salt | nonce | ciphertext(AES-GCM)
```

Ключ шифрования не хранится: он каждый раз выводится из мастер-пароля и соли. Неверный пароль — GCM не расшифрует текст, и отличить «не тот пароль» от «файл испорчен» можно достоверно.

## Лицензия

MIT
