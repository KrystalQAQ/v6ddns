package gui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// appTheme is the default Fyne theme with a calmer, higher-contrast palette and
// slightly roomier spacing. Only a few colors are overridden; everything else
// (fonts, icons, platform integration) stays with the system theme.
type appTheme struct {
	fyne.Theme
}

func newAppTheme() fyne.Theme { return appTheme{Theme: theme.DefaultTheme()} }

func (t appTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	dark := variant == theme.VariantDark
	switch name {
	case theme.ColorNamePrimary:
		if dark {
			return color.NRGBA{R: 0x5b, G: 0xb8, B: 0xff, A: 0xff}
		}
		return color.NRGBA{R: 0x0b, G: 0x63, B: 0xd8, A: 0xff}
	case theme.ColorNameBackground:
		if dark {
			return color.NRGBA{R: 0x0e, G: 0x13, B: 0x1a, A: 0xff}
		}
		return color.NRGBA{R: 0xf3, G: 0xf6, B: 0xfa, A: 0xff}
	case theme.ColorNameHeaderBackground:
		if dark {
			return color.NRGBA{R: 0x12, G: 0x19, B: 0x21, A: 0xff}
		}
		return color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
	case theme.ColorNameMenuBackground:
		if dark {
			return color.NRGBA{R: 0x11, G: 0x18, B: 0x20, A: 0xff}
		}
		return color.NRGBA{R: 0xfa, G: 0xfb, B: 0xfd, A: 0xff}
	case theme.ColorNameForeground:
		if dark {
			return color.NRGBA{R: 0xe6, G: 0xed, B: 0xf3, A: 0xff}
		}
		return color.NRGBA{R: 0x18, G: 0x22, B: 0x2d, A: 0xff}
	case theme.ColorNameButton:
		if dark {
			return color.NRGBA{R: 0x1a, G: 0x23, B: 0x2c, A: 0xff}
		}
		return color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
	case theme.ColorNameInputBackground:
		if dark {
			return color.NRGBA{R: 0x15, G: 0x1d, B: 0x26, A: 0xff}
		}
		return color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
	case theme.ColorNameSeparator:
		if dark {
			return color.NRGBA{R: 0x27, G: 0x32, B: 0x3e, A: 0xff}
		}
		return color.NRGBA{R: 0xe2, G: 0xe8, B: 0xef, A: 0xff}
	case theme.ColorNamePlaceHolder:
		if dark {
			return color.NRGBA{R: 0x9a, G: 0xa5, B: 0xb1, A: 0xff}
		}
		return color.NRGBA{R: 0x6b, G: 0x77, B: 0x85, A: 0xff}
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 0x9a, G: 0xa5, B: 0xb1, A: 0xff}
	case theme.ColorNameSuccess:
		return color.NRGBA{R: 0x2e, G: 0xa0, B: 0x6a, A: 0xff}
	case theme.ColorNameError:
		return color.NRGBA{R: 0xd9, G: 0x3a, B: 0x3a, A: 0xff}
	case theme.ColorNameWarning:
		return color.NRGBA{R: 0xd8, G: 0x8a, B: 0x1a, A: 0xff}
	}
	return t.Theme.Color(name, variant)
}

func (t appTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 9
	case theme.SizeNameInnerPadding:
		return 12
	case theme.SizeNameText:
		return 15
	case theme.SizeNameHeadingText:
		return 21
	case theme.SizeNameSubHeadingText:
		return 17
	case theme.SizeNameCaptionText:
		return 12
	case theme.SizeNameLineSpacing:
		return 6
	case theme.SizeNameSeparatorThickness:
		return 1
	case theme.SizeNameInputBorder:
		return 1
	case theme.SizeNameInputRadius:
		return 8
	case theme.SizeNameButtonRadius:
		return 8
	case theme.SizeNameCardRadius:
		return 12
	case theme.SizeNameSelectionRadius:
		return 8
	}
	return t.Theme.Size(name)
}

// uiColor resolves a theme color on the current UI goroutine.
func uiColor(name fyne.ThemeColorName) color.Color {
	settings := fyne.CurrentApp().Settings()
	return settings.Theme().Color(name, settings.ThemeVariant())
}

func successColor() color.Color { return uiColor(theme.ColorNameSuccess) }
func errorColor() color.Color   { return uiColor(theme.ColorNameError) }
func warningColor() color.Color { return uiColor(theme.ColorNameWarning) }
func primaryColor() color.Color { return uiColor(theme.ColorNamePrimary) }
func mutedColor() color.Color   { return uiColor(theme.ColorNamePlaceHolder) }

// statusDot creates a small colored dot used next to status text.
func statusDot(col color.Color) *canvas.Circle {
	return canvas.NewCircle(col)
}

// dotBox gives a status dot a fixed footprint: canvas shapes report a 1x1
// minimum, so they need an explicit wrapper inside Box layouts.
func dotBox(dot *canvas.Circle) fyne.CanvasObject {
	return container.NewGridWrap(fyne.NewSize(10, 10), dot)
}

func setDot(dot *canvas.Circle, col color.Color) {
	if dot == nil {
		return
	}
	dot.FillColor = col
	dot.Refresh()
}

// mutedText renders secondary copy at caption size. canvas.Text does not wrap,
// so keep these strings short.
func mutedText(s string) *canvas.Text {
	t := canvas.NewText(s, mutedColor())
	t.TextSize = 13
	return t
}

// sectionTitle is a card heading with a little more weight than Fyne's default.
func sectionTitle(s string) *widget.Label {
	return widget.NewLabelWithStyle(s, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
}

// panel is a flat white card with a hairline border and a soft shadow. Fyne's
// built-in Card paints with ColorNameBackground, which is the same color as the
// page background in this theme, so cards would otherwise vanish into the page.
func panel(title, subtitle string, content fyne.CanvasObject) fyne.CanvasObject {
	bg := canvas.NewRectangle(uiColor(theme.ColorNameInputBackground))
	bg.CornerRadius = 12
	bg.StrokeColor = uiColor(theme.ColorNameSeparator)
	bg.StrokeWidth = 1
	bg.Shadow = canvas.Shadow{
		Color:      uiColor(theme.ColorNameShadow),
		BlurRadius: 14,
		Offset:     fyne.NewPos(0, 3),
		Variant:    canvas.DropShadow,
	}

	heading := canvas.NewText(title, uiColor(theme.ColorNameForeground))
	heading.TextSize = 18
	heading.TextStyle = fyne.TextStyle{Bold: true}
	items := []fyne.CanvasObject{heading}
	if subtitle != "" {
		items = append(items, mutedText(subtitle))
	}
	items = append(items, widget.NewSeparator(), content)

	return container.NewStack(bg, container.NewPadded(container.NewVBox(items...)))
}
