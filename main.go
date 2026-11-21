package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/WOLFraMix/coffer/internal/app"
	"github.com/WOLFraMix/coffer/internal/vault"
)

// Wails встраивает собранный фронтенд (frontend/dist) прямо в бинарник:
// готовый exe не требует ни браузера, ни локального сервера.
// См. https://pkg.go.dev/embed
//
//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Путь к сейфу: %APPDATA%/Coffer/coffer.cof на Windows.
	path, err := vault.DefaultPath()
	if err != nil {
		log.Fatal(err)
	}

	svc := app.NewService(path)

	a := application.New(application.Options{
		Name:        "Coffer",
		Description: "Локальный аутентификатор 2FA — коды TOTP без облаков",
		Services: []application.Service{
			application.NewService(svc),
		},
		Assets: application.AssetOptions{
			// AssetFileServerFS раздаёт встроенные файлы фронтенда.
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
	})

	// Одно окно под наш список кодов.
	a.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:  "Coffer",
		Width:  520,
		Height: 640,
		// Цвет фона совпадает с фоном UI (#12141a), чтобы не мигало белым при загрузке.
		BackgroundColour: application.NewRGB(18, 20, 26),
		URL:              "/",
	})

	// Блокируем выполнение до закрытия приложения.
	if err := a.Run(); err != nil {
		log.Fatal(err)
	}
}
