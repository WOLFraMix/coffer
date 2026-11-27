package main

import (
	"bytes"
	"embed"
	"image"
	"image/color"
	"image/png"
	"log"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/WOLFraMix/coffer/internal/app"
	"github.com/WOLFraMix/coffer/internal/vault"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
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
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
	})
	svc.SetFilePicker(wailsPicker{a: a})

	win := a.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "Coffer",
		Width:            520,
		Height:           640,
		BackgroundColour: application.NewRGB(18, 20, 26),
		URL:              "/",
	})

	// --- Трей ---
	tray := a.SystemTray.New()
	tray.SetIcon(trayIcon())
	tray.SetTooltip("Coffer — коды 2FA")

	// Меню: собрать -> повесить обработчики -> назначить трею.
	// OnClick у MenuItem принимает func(*Context): контекст не нужен,
	// но сигнатуру менять нельзя — иначе не скомпилируется.
	menu := application.NewMenu()
	menu.Add("Показать окно").OnClick(func(*application.Context) {
		win.Show()
		win.Focus()
	})
	menu.Add("Заблокировать сейчас").OnClick(func(*application.Context) {
		svc.Lock()
	})
	menu.AddSeparator()
	menu.Add("Выход").OnClick(func(*application.Context) {
		a.Quit()
	})
	tray.SetMenu(menu)

	// Левый клик по иконке: показать/спрятать окно.
	tray.OnClick(func() {
		tray.ToggleWindow()
	})
	tray.Show()

	// --- Закрытие окна = сворачивание в трей ---
	// Перехватываем событие закрытия: окно не уничтожаем, а прячем.
	// Приложение остаётся жить в трее — как менеджер паролей и должен.
	win.OnWindowEvent(events.Common.WindowClosing, func(e *application.WindowEvent) {
		e.Cancel() // отменяем закрытие: окно не уничтожается
		win.Hide() // прячем — приложение продолжает жить в трее
	})

	if err := a.Run(); err != nil {
		log.Fatal(err)
	}
}

// trayIcon рисует иконку 32×32 в коде: синий круг + белый замок.
func trayIcon() []byte {
	const size = 32
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	bg := color.RGBA{R: 0x4f, G: 0x7c, B: 0xff, A: 0xff}
	fg := color.RGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
	transparent := color.RGBA{A: 0}

	// Круг с прозрачным краем.
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx, dy := x-16, y-16
			if dx*dx+dy*dy <= 15*15 {
				img.Set(x, y, bg)
			} else {
				img.Set(x, y, transparent)
			}
		}
	}
	// Дужка замка: кольцо радиуса 4 вокруг (16,13), верхняя половина.
	for y := 0; y < size; y++ {
		if y > 13 {
			break
		}
		for x := 0; x < size; x++ {
			dx, dy := x-16, y-13
			d2 := dx*dx + dy*dy
			if d2 <= 16 && d2 >= 4 {
				img.Set(x, y, fg)
			}
		}
	}
	// Корпус замка.
	for y := 13; y < 22; y++ {
		for x := 10; x < 22; x++ {
			img.Set(x, y, fg)
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil
	}
	return buf.Bytes()
}

// wailsPicker — адаптер системных диалогов Wails под интерфейс
// app.FilePicker. Всё знание о Wails-диалогах живёт здесь.
type wailsPicker struct {
	a *application.App
}

func (p wailsPicker) SaveFile(defaultName string) (string, error) {
	d := p.a.Dialog.SaveFileWithOptions(&application.SaveFileDialogOptions{
		Title:                "Сохранить резервную копию",
		Filename:             defaultName,
		CanCreateDirectories: true,
		Filters: []application.FileFilter{
			{DisplayName: "Резервная копия Coffer", Pattern: "*.cofbak"},
		},
	})
	return d.PromptForSingleSelection()
}

func (p wailsPicker) OpenFile() (string, error) {
	d := p.a.Dialog.OpenFileWithOptions(&application.OpenFileDialogOptions{
		Title:                "Выберите резервную копию",
		CanChooseFiles:       true,
		CanChooseDirectories: false,
		CanCreateDirectories: true,
		Filters: []application.FileFilter{
			{DisplayName: "Резервная копия Coffer", Pattern: "*.cofbak"},
		},
	})
	return d.PromptForSingleSelection()
}
