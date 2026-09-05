//go:build windows

package main

import (
 "embed"
 "fmt"
 "os"
 "github.com/wailsapp/wails/v2"
 "github.com/wailsapp/wails/v2/pkg/logger"
 "github.com/wailsapp/wails/v2/pkg/options"
 "github.com/wailsapp/wails/v2/pkg/options/assetserver"
 wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
 app := newApp()
 err := wails.Run(&options.App{
  Title: "Sentinel", Width: 1120, Height: 800, MinWidth: 800, MinHeight: 620,
  BackgroundColour: options.NewRGB(248, 247, 249),
  AssetServer: &assetserver.Options{Assets: assets},
  OnStartup: app.startup, Bind: []interface{}{app},
  LogLevelProduction: logger.ERROR,
  EnableDefaultContextMenu: false, EnableFraudulentWebsiteDetection: false,
  DragAndDrop: &options.DragAndDrop{DisableWebViewDrop: true},
  SingleInstanceLock: &options.SingleInstanceLock{
   UniqueId: "d5306e6b-65c6-4ca0-8fd0-53f6e22adb24",
   OnSecondInstanceLaunch: func(_ options.SecondInstanceData) {
    app.ctxMu.RLock(); ctx := app.ctx; app.ctxMu.RUnlock()
    if ctx != nil { wruntime.WindowUnminimise(ctx); wruntime.WindowShow(ctx) }
   },
  },
 })
 if err != nil {
  fmt.Fprintln(os.Stderr, "Sentinel could not start. Check WebView2 and the build instructions.")
  os.Exit(1)
 }
}
