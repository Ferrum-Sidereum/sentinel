// Command sentinel-gui is a native Win32 companion app for sentinel.
// Pure Go, no cgo, no browser: tabs for Secrets / Scan / Audit / Policy.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"gopkg.in/yaml.v3"
	"sentinel/internal/audit"
	"sentinel/internal/keyring"
	"sentinel/internal/placeholder"
	"sentinel/internal/policy"
	"sentinel/internal/scrubber"
	"sentinel/internal/vault"
)

var (
	user32             = windows.NewLazySystemDLL("user32.dll")
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	pCreateWindowExW   = user32.NewProc("CreateWindowExW")
	pDefWindowProcW    = user32.NewProc("DefWindowProcW")
	pDispatchMessageW  = user32.NewProc("DispatchMessageW")
	pGetMessageW       = user32.NewProc("GetMessageW")
	pLoadCursorW       = user32.NewProc("LoadCursorW")
	pPostQuitMessage   = user32.NewProc("PostQuitMessage")
	pRegisterClassExW  = user32.NewProc("RegisterClassExW")
	pSendMessageW      = user32.NewProc("SendMessageW")
	pPostMessageW      = user32.NewProc("PostMessageW")
	pSetWindowTextW    = user32.NewProc("SetWindowTextW")
	pGetWindowTextW    = user32.NewProc("GetWindowTextW")
	pGetWindowTextLenW = user32.NewProc("GetWindowTextLengthW")
	pShowWindow        = user32.NewProc("ShowWindow")
	pUpdateWindow      = user32.NewProc("UpdateWindow")
	pTranslateMessage  = user32.NewProc("TranslateMessage")
	pMessageBoxW       = user32.NewProc("MessageBoxW")
	pCreateMutexW      = kernel32.NewProc("CreateMutexW")
	pGetLastError      = kernel32.NewProc("GetLastError")
	pFindWindowW       = user32.NewProc("FindWindowW")
	pSetForegroundWnd  = user32.NewProc("SetForegroundWindow")
	pPeekMessageW      = user32.NewProc("PeekMessageW")
	pSetTimer          = user32.NewProc("SetTimer")
	pKillTimer         = user32.NewProc("KillTimer")
	pDestroyWindow     = user32.NewProc("DestroyWindow")
	pLoadImageW        = user32.NewProc("LoadImageW")
	pGetTickCount      = kernel32.NewProc("GetTickCount")
	pNoGhost           = user32.NewProc("DisableProcessWindowsGhosting")
	pSendMsgTimeout    = user32.NewProc("SendMessageTimeoutW")
)
const (
	WS_OVERLAPPEDWINDOW = 0x00CF0000
	WS_MAXIMIZEBOX      = 0x00010000
	WS_THICKFRAME       = 0x00040000
	WS_VISIBLE          = 0x10000000
	WS_CHILD            = 0x40000000
	WS_BORDER           = 0x00800000
	WS_VSCROLL          = 0x00200000
	ES_MULTILINE        = 0x0004
	ES_AUTOVSCROLL      = 0x0040
	ES_READONLY         = 0x0800
	SS_CENTER           = 0x0001
	LBS_NOTIFY          = 0x0001
	LBN_SELCHANGE       = 1
	LB_SETCURSEL        = 0x0186
	WM_DESTROY          = 0x0002
	WM_COMMAND          = 0x0111
	WM_NOTIFY           = 0x004E
	WM_SIZE             = 0x0005
	WM_TIMER            = 0x0113
	WM_NULL             = 0x0000
	SMTO_ABORTIFHUNG    = 0x0002
	WM_USER             = 0x0400
	WM_LOAD_DONE        = WM_USER + 1
	WM_WORK_DONE        = WM_USER + 2
	loadMinShowMs       = 1200
	TCN_SELCHANGE       = -551
	TCM_INSERTITEMW     = 0x1307
	TCM_SETCURSEL       = 0x130C
	TCM_GETCURSEL       = 0x130B
	LB_ADDSTRING        = 0x0180
	LB_GETCURSEL        = 0x0188
	LB_RESETCONTENT     = 0x0184
	LB_GETTEXT          = 0x0189
	LB_GETTEXTLEN       = 0x018A
	SW_SHOW             = 5
	IDC_ARROW           = 32512
	IMAGE_ICON          = 1
	LR_LOADFROMFILE     = 0x10
	ID_ICON             = 1
)

const (
	idSide = 100 + iota
	idList
	idNameEdit
	idValEdit
	idAddBtn
	idDelBtn
	idPhOut
	idScanEdit
	idScanBtn
	idScanOut
	idReName
	idReEdit
	idReAddBtn
	idReDelBtn
	idReList
	idTglList
	idTglEdit
	idTglBtn
	idAuditOut
	idAuditBtn
)

var (
	hMain, hSide uintptr
	hLoading     uintptr
	loaded       bool
	// loadStartMs фиксирует момент старта загрузки; оверлей показываем
	// минимум loadMinShowMs, иначе его невозможно увидеть (данные локальные).
	loadStartMs    uint32
	wndProcPtr     uintptr
	pages             [4][]uintptr
	secrets           []string
	prePatterns       map[string]string
	preEntities       map[string]policy.EntityRule
	preErr            string
	curTab            int
	leakCount         int
	hIcon             uintptr
)

func wstr(s string) *uint16 { p, _ := windows.UTF16PtrFromString(s); return p }

func sendMsg(h uintptr, msg uint32, w, l uintptr) uintptr {
	r, _, _ := pSendMessageW.Call(h, uintptr(msg), w, l)
	return r
}

// sendStr — единственный корректный путь слать строки: конвертация
// UTF16 и использование указателя обязаны быть в одном выражении .Call.
// Передача uintptr через обёртки (как было раньше) позволяет GC собрать
// буфер прямо во время SendMessage -> редкие висения/порча памяти.
func sendStr(h uintptr, msg uint32, s string) uintptr {
	p, _ := windows.UTF16PtrFromString(s)
	r, _, _ := pSendMessageW.Call(h, uintptr(msg), 0, uintptr(unsafe.Pointer(p)))
	return r
}

func mkCtl(class, text string, style uintptr, x, y, w, h int32, parent uintptr, id int) uintptr {
	c, _ := windows.UTF16PtrFromString(class)
	t, _ := windows.UTF16PtrFromString(text)
	r, _, _ := pCreateWindowExW.Call(0,
		uintptr(unsafe.Pointer(c)),
		uintptr(unsafe.Pointer(t)),
		style, uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		parent, uintptr(id), 0, 0)
	return r
}

func getText(h uintptr) string {
	n, _, _ := pGetWindowTextLenW.Call(h)
	buf := make([]uint16, n+1)
	pGetWindowTextW.Call(h, uintptr(unsafe.Pointer(&buf[0])), n+1)
	return windows.UTF16ToString(buf)
}

func setText(h uintptr, s string) {
	p, _ := windows.UTF16PtrFromString(s)
	pSetWindowTextW.Call(h, uintptr(unsafe.Pointer(p)))
}

func dataDir() string { home, _ := os.UserHomeDir(); return filepath.Join(home, ".sentinel") }

func openStore() (*vault.Store, error) {
	key, err := keyring.LoadOrCreate()
	if err != nil {
		return nil, err
	}
	return vault.Open(filepath.Join(dataDir(), "vault.db"), key)
}

const (
	workSecrets = 1 + iota
	workAdd
	workDel
	workScan
	workPatterns
	workToggles
)

// Фоновая работа: весь IO (vault/keyring/policy/scan) идёт в горутине,
// UI-поток только рисует. Иначе любая заминка хранилища вешает окно.
// В полёте только одна работа (workBusy); результаты — в workErr/workText,
// workNum, публикация через очередь сообщений.
var (
	workBusy  bool
	workErr   string
	workText  string
	workNum   int
	workName  string
)

func postWork(id int, tag string, job func()) {
	if workBusy {
		trace("work skip busy " + tag)
		return
	}
	workBusy = true
	workErr, workText, workName, workNum = "", "", "", 0
	trace("work start " + tag)
	go func() {
		job()
		trace("work posting " + tag)
		pPostMessageW.Call(hMain, uintptr(WM_WORK_DONE), uintptr(id), 0)
	}()
}

func applyWork(id int) {
	workBusy = false
	trace("work apply")
	switch id {
	case workSecrets:
		if workErr != "" {
			msgbox(workErr)
		}
		paintSecrets()
	case workAdd:
		if workErr != "" {
			msgbox(workErr)
			break
		}
		setText(pages[0][2], "")
		setText(pages[0][3], workText)
		paintSecrets()
	case workDel:
		if workErr != "" {
			msgbox(workErr)
		}
		paintSecrets()
	case workScan:
		leakCount += workNum
		setText(pages[1][2], workText)
	case workPatterns:
		if workErr != "" {
			msgbox(workErr)
		}
		paintPatterns()
	case workToggles:
		if workErr != "" {
			msgbox(workErr)
		}
		paintToggles()
	}
}

func msgbox(s string) { pMessageBoxW.Call(hMain, uintptr(unsafe.Pointer(wstr(s))), uintptr(unsafe.Pointer(wstr("sentinel"))), 0) }
// --- actions ---
func paintSecrets() {
	sendMsg(pages[0][0], LB_RESETCONTENT, 0, 0)
	for _, n := range secrets {
		sendStr(pages[0][0], LB_ADDSTRING, n+"  "+placeholder.Canonical(n))
	}
}

func paintPatterns() {
	sendMsg(pages[1][4], LB_RESETCONTENT, 0, 0)
	for name, re := range prePatterns {
		sendStr(pages[1][4], LB_ADDSTRING, name+" :: "+re)
	}
}

func paintToggles() {
	sendMsg(pages[2][0], LB_RESETCONTENT, 0, 0)
	for name, e := range preEntities {
		state := "ON"
		if e.ToLLM == "off" || e.ToLLM == "" {
			state = "OFF"
		}
		sendStr(pages[2][0], LB_ADDSTRING, "["+state+"] "+name+" -> "+e.ToLLM)
	}
}

func refreshSecrets() {
	postWork(workSecrets, "secrets", func() {
		st, err := openStore()
		if err != nil {
			workErr = "store: " + err.Error()
			return
		}
		names, _ := st.List()
		st.Close()
		secrets = names
	})
}

func addSecret() {
	name := strings.TrimSpace(getText(pages[0][1]))
	val := getText(pages[0][2])
	if name == "" || val == "" {
		msgbox("заполни имя и значение")
		return
	}
	cname := placeholder.Canonical(name)
	csafe := placeholder.Safe(name)
	postWork(workAdd, "add", func() {
		st, err := openStore()
		if err != nil {
			workErr = "store: " + err.Error()
			return
		}
		v := []byte(val)
		err = st.Put(vault.Secret{Name: cname, Value: v})
		for i := range v {
			v[i] = 0
		}
		if err != nil {
			st.Close()
			workErr = "put: " + err.Error()
			return
		}
		if l, _ := audit.Open(filepath.Join(dataDir(), "audit.jsonl")); l != nil {
			l.Log("gui", "secret.add", map[string]any{"name": name})
			l.Close()
		}
		names, _ := st.List()
		st.Close()
		secrets = names
		workText = "в env вставь:\r\n" + cname + "\r\nили " + csafe
	})
}

func delSecret() {
	i := int(sendMsg(pages[0][0], LB_GETCURSEL, 0, 0))
	if i < 0 || i >= len(secrets) {
		msgbox("выбери секрет в списке")
		return
	}
	target := secrets[i]
	postWork(workDel, "del", func() {
		st, err := openStore()
		if err != nil {
			workErr = "store: " + err.Error()
			return
		}
		if err := st.Delete(target); err != nil {
			st.Close()
			workErr = "delete: " + err.Error()
			return
		}
		names, _ := st.List()
		st.Close()
		secrets = names
	})
}

func policyPath() string { return filepath.Join(dataDir(), "policy.yaml") }

func runScan() {
	text := getText(pages[1][0])
	postWork(workScan, "scan", func() {
		p, _ := policy.Load(policyPath())
		allow := map[string]bool{}
		for _, v := range p.Allowlist.Values {
			allow[v] = true
		}
		vvals := map[string]string{}
		if st, err := openStore(); err == nil {
			if names, err := st.List(); err == nil {
				for _, n := range names {
					if sec, err := st.Get(n); err == nil {
						vvals[n] = string(sec.Value)
					}
				}
			}
			st.Close()
		}
		findings := scrubber.Scan(text, vvals, allow)
		var sb strings.Builder
		for _, f := range findings {
			fmt.Fprintf(&sb, "%s [%s conf=%.2f] %q\r\n", f.Type, f.Detector, f.Confidence, f.Value)
		}
		workNum = len(findings)
		if sb.Len() == 0 {
			sb.WriteString("чисто — находок нет")
		}
		workText = sb.String()
	})
}
func refreshPatterns() {
	postWork(workPatterns, "patterns", func() {
		p, _ := policy.Load(policyPath())
		prePatterns = p.CustomPatterns
		preEntities = p.Entities
	})
}

func savePolicyYAML(p policy.Policy) error {
	b, err := yaml.Marshal(&p)
	if err != nil {
		return err
	}
	return os.WriteFile(policyPath(), b, 0o600)
}

func addPattern() {
	name := strings.TrimSpace(getText(pages[1][5]))
	re := strings.TrimSpace(getText(pages[1][6]))
	if name == "" || re == "" {
		msgbox("заполни имя и regex")
		return
	}
	if _, err := regexp.Compile(re); err != nil {
		msgbox("regex ошибка: " + err.Error())
		return
	}
	p, _ := policy.Load(policyPath())
	if p.CustomPatterns == nil {
		p.CustomPatterns = map[string]string{}
	}
	p.CustomPatterns[name] = re
	postWork(workPatterns, "addpattern", func() {
		if err := savePolicyYAML(p); err != nil {
			workErr = "write: " + err.Error()
			return
		}
		np, _ := policy.Load(policyPath())
		prePatterns = np.CustomPatterns
		preEntities = np.Entities
	})
}

func delPattern() {
	name := strings.TrimSpace(getText(pages[1][5]))
	if name == "" {
		msgbox("впиши имя паттерна для удаления")
		return
	}
	p, _ := policy.Load(policyPath())
	delete(p.CustomPatterns, name)
	postWork(workPatterns, "delpattern", func() {
		if err := savePolicyYAML(p); err != nil {
			workErr = "write: " + err.Error()
			return
		}
		np, _ := policy.Load(policyPath())
		prePatterns = np.CustomPatterns
		preEntities = np.Entities
	})
}

func refreshToggles() {
	postWork(workToggles, "toggles", func() {
		p, _ := policy.Load(policyPath())
		preEntities = p.Entities
	})
}

func toggleEntity() {
	name := strings.TrimSpace(getText(pages[2][1]))
	if name == "" {
		msgbox("впиши имя сущности (напр. EMAIL)")
		return
	}
	p, _ := policy.Load(policyPath())
	e := p.Entities[name]
	if e.ToLLM == "off" || e.ToLLM == "" {
		e.ToLLM = "mask"
		e.ToUntrusted = "mask"
		if e.Detector == nil {
			e.Detector = []string{"regex"}
		}
	} else {
		e.ToLLM = "off"
		e.ToUntrusted = "off"
	}
	if p.Entities == nil {
		p.Entities = map[string]policy.EntityRule{}
	}
	p.Entities[name] = e
	postWork(workToggles, "toggle", func() {
		if err := savePolicyYAML(p); err != nil {
			workErr = "write: " + err.Error()
			return
		}
		np, _ := policy.Load(policyPath())
		preEntities = np.Entities
	})
}

func loadAudit() {
	b, err := os.ReadFile(filepath.Join(dataDir(), "audit.jsonl"))
	if err != nil {
		setText(pages[3][0], "audit.jsonl: "+err.Error())
		return
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > 100 {
		lines = lines[len(lines)-100:]
	}
	head := fmt.Sprintf("утечек за сессию: %d\r\n---\r\n", leakCount)
	setText(pages[3][0], head+strings.Join(lines, "\r\n"))
}

// --- window ---
func showTab(n int) {
	curTab = n
	for i, pg := range pages {
		for _, c := range pg {
			pShowWindow.Call(c, map[bool]uintptr{true: 5, false: 0}[i == curTab])
		}
	}
	if curTab == 3 {
		loadAudit()
	}
}

func setIcon(h uintptr) {
	if hIcon == 0 {
		exe, _ := os.Executable()
		dir := filepath.Dir(exe)
		for _, p := range []string{filepath.Join(dir, "sentinel.ico"), "sentinel.ico"} {
			if _, err := os.Stat(p); err != nil {
				continue
			}
			ic, _, _ := pLoadImageW.Call(0, uintptr(unsafe.Pointer(wstr(p))), IMAGE_ICON, 32, 32, LR_LOADFROMFILE)
			if ic != 0 {
				hIcon = ic
				break
			}
		}
	}
	if hIcon != 0 {
		const WM_SETICON = 0x0080
		sendMsg(h, WM_SETICON, 1, hIcon)
		sendMsg(h, WM_SETICON, 0, hIcon)
	}
}

func setContentVisible(v bool) {
	show := map[bool]uintptr{true: 5, false: 0}[v]
	hide := map[bool]uintptr{true: 0, false: 5}[v]
	pShowWindow.Call(hLoading, hide)
	pShowWindow.Call(hSide, show)
	for i, pg := range pages {
		for _, c := range pg {
			if i == curTab && v {
				pShowWindow.Call(c, 5)
			} else {
				pShowWindow.Call(c, 0)
			}
		}
	}
}

func tickMs() uint32 { r, _, _ := pGetTickCount.Call(); return uint32(r) }

func finishLoading() {
	if loaded {
		return
	}
	// Минимальное время показа загрузочного экрана: иначе при локальных
	// данных оверлей мелькает на миллисекунды и его не видно.
	if el := tickMs() - loadStartMs; el < loadMinShowMs {
		pSetTimer.Call(hMain, 2, uintptr(loadMinShowMs-el), 0)
		return
	}
	loaded = true
	trace("finish")
	pKillTimer.Call(hMain, 1)
	pKillTimer.Call(hMain, 2)
	paintSecrets()
	paintPatterns()
	paintToggles()
	if preErr != "" {
		setText(pages[0][5], "загрузка: "+preErr)
	} else {
		setText(pages[0][5], "плейсхолдер для env появится здесь")
	}
	setContentVisible(true)
	showTab(0)
}

func loadDataAsync(h uintptr) {
	go func() {
		trace("load start")
		if st, err := openStore(); err == nil {
			secrets, _ = st.List()
			st.Close()
		} else {
			preErr = err.Error()
		}
		d := policy.Default()
		prePatterns = d.CustomPatterns
		preEntities = d.Entities
		if p, err := policy.Load(policyPath()); err == nil {
			if len(p.CustomPatterns) > 0 {
				prePatterns = p.CustomPatterns
			}
			if len(p.Entities) > 0 {
				preEntities = p.Entities
			}
		} else if preErr == "" {
			preErr = err.Error()
		}
		trace("load posting")
		pPostMessageW.Call(h, uintptr(WM_LOAD_DONE), 0, 0)
	}()
}

func wndProc(h uintptr, msg uint32, w, l uintptr) uintptr {

	switch msg {
	case WM_DESTROY:
		if h == hMain {
			pPostQuitMessage.Call(0)
		}
		return 0
	case WM_LOAD_DONE:
		trace("wm_load_done")
		finishLoading()
		return 0
	case WM_TIMER:
		trace("wm_timer")
		finishLoading()
		return 0
	case WM_WORK_DONE:
		applyWork(int(w))
		return 0
	case WM_COMMAND:
		id := int(w & 0xFFFF)
		code := int((w >> 16) & 0xFFFF)
		switch id {
		case idSide:
			if code == LBN_SELCHANGE {
				showTab(int(sendMsg(hSide, LB_GETCURSEL, 0, 0)))
			}
		case idAddBtn:
			addSecret()
		case idDelBtn:
			delSecret()
		case idScanBtn:
			runScan()
		case idReAddBtn:
			addPattern()
		case idReDelBtn:
			delPattern()
		case idTglBtn:
			toggleEntity()
		case idAuditBtn:
			loadAudit()
		}
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(h, uintptr(msg), w, l)
	return r
}

type wndClassEx struct {
	size, style     uint32
	proc            uintptr
	clsExtra, wndEx int32
	inst            syscall.Handle
	icon, cursor    uintptr
	brBackground    uintptr
	menu, clsName   *uint16
	iconSm          uintptr
}
func trace(s string) {
	f, _ := os.OpenFile(filepath.Join(os.TempDir(), "sentinel-gui-trace.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if f != nil {
		f.WriteString(s + "\n")
		f.Close()
	}
}

// hungWatchdog: через 12с после старта пингует UI-поток через
// SendMessageTimeout с другого потока. Если памп мёртв — пишет все
// Go-стеки в трейс: видно точную инструкцию зависания.
func hungWatchdog(h uintptr) {
	time.Sleep(12 * time.Second)
	var res uintptr
	r, _, _ := pSendMsgTimeout.Call(h, uintptr(WM_NULL), 0, 0, uintptr(SMTO_ABORTIFHUNG), 2000, uintptr(unsafe.Pointer(&res)))
	if r == 0 {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		f, _ := os.OpenFile(filepath.Join(os.TempDir(), "sentinel-gui-trace.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if f != nil {
			f.WriteString("=== HUNG, goroutine dump ===\n")
			f.Write(buf[:n])
			f.WriteString("=== end dump ===\n")
			f.Close()
		}
	} else {
		trace("watchdog alive")
	}
}

func main() {
	trace("start")
	// Без ghost-окна: если UI-поток встанет, Windows не будет рисовать
	// вторую чёрную заглушку "(Не отвечает)" — окно просто замрёт.
	pNoGhost.Call()
	_, _, _ = pCreateMutexW.Call(0, 1, uintptr(unsafe.Pointer(wstr(`Local\SentinelGuiSingleInstance`))))
	if e, _, _ := pGetLastError.Call(); e == 183 {
		trace("already running, foregrounding")
		if h, _, _ := pFindWindowW.Call(uintptr(unsafe.Pointer(wstr("SentinelGui"))), 0); h != 0 {
			pShowWindow.Call(h, 9)
			pSetForegroundWnd.Call(h)
		}
		return
	}
	trace("mutex ok")
	cursor, _, _ := pLoadCursorW.Call(0, IDC_ARROW)
	// wndProcPtr держим в глобале: callback обязан жить весь процесс,
	// локалку после RegisterClass теоретически может собрать GC.
	wndProcPtr = syscall.NewCallback(wndProc)
	cls := wndClassEx{proc: wndProcPtr, cursor: cursor, brBackground: 16, clsName: wstr("SentinelGui")}
	cls.size = uint32(unsafe.Sizeof(cls))
	pRegisterClassExW.Call(uintptr(unsafe.Pointer(&cls)))
	trace("class ok")
	hMain, _, _ = pCreateWindowExW.Call(0,
		uintptr(unsafe.Pointer(wstr("SentinelGui"))),
		uintptr(unsafe.Pointer(wstr("sentinel"))),
		WS_OVERLAPPEDWINDOW|WS_VISIBLE, 200, 150, 780, 540, 0, 0, 0, 0)
	trace("hmain created")
	setIcon(hMain)
	trace("icon ok")
	pShowWindow.Call(hMain, SW_SHOW)
	pUpdateWindow.Call(hMain)
	trace("window ok")
	hSide = mkCtl("LISTBOX", "", WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|LBS_NOTIFY, 8, 8, 150, 480, hMain, idSide)
	for _, t := range []string{"🔑 Токены", "🛡 Фильтры", "☰ Вкл/Выкл", "📡 Утечки"} {
		sendStr(hSide, LB_ADDSTRING, t)
	}
	sendMsg(hSide, LB_SETCURSEL, 0, 0)
	X := int32(168)
	W := int32(588)
	pages[0] = []uintptr{
		mkCtl("LISTBOX", "", WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|LBS_NOTIFY, X, 8, W, 220, hMain, idList),
		mkCtl("EDIT", "имя", WS_CHILD|WS_VISIBLE|WS_BORDER, X, 236, 180, 26, hMain, idNameEdit),
		mkCtl("EDIT", "значение", WS_CHILD|WS_VISIBLE|WS_BORDER, X+188, 236, 220, 26, hMain, idValEdit),
		mkCtl("BUTTON", "Добавить", WS_CHILD|WS_VISIBLE, X, 268, 100, 28, hMain, idAddBtn),
		mkCtl("BUTTON", "Удалить", WS_CHILD|WS_VISIBLE, X+108, 268, 100, 28, hMain, idDelBtn),
		mkCtl("EDIT", "плейсхолдер для env появится здесь", WS_CHILD|WS_VISIBLE|WS_BORDER|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY, X, 304, W, 184, hMain, idPhOut),
	}
	pages[1] = []uintptr{
		mkCtl("EDIT", "вставь текст для проверки…", WS_CHILD|WS_BORDER|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL, X, 8, W, 120, hMain, idScanEdit),
		mkCtl("BUTTON", "Проверить", WS_CHILD, X, 134, 120, 28, hMain, idScanBtn),
		mkCtl("EDIT", "", WS_CHILD|WS_BORDER|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY, X, 168, W, 120, hMain, idScanOut),
		mkCtl("STATIC", "свой regex:", WS_CHILD, X, 296, 100, 20, hMain, 0),
		mkCtl("LISTBOX", "", WS_CHILD|WS_BORDER|WS_VSCROLL, X, 318, W, 90, hMain, idReList),
		mkCtl("EDIT", "имя", WS_CHILD|WS_BORDER, X, 414, 150, 26, hMain, idReName),
		mkCtl("EDIT", "regex", WS_CHILD|WS_BORDER, X+158, 414, 250, 26, hMain, idReEdit),
		mkCtl("BUTTON", "+", WS_CHILD, X+416, 414, 40, 26, hMain, idReAddBtn),
		mkCtl("BUTTON", "-", WS_CHILD, X+460, 414, 40, 26, hMain, idReDelBtn),
	}
	pages[2] = []uintptr{
		mkCtl("LISTBOX", "", WS_CHILD|WS_BORDER|WS_VSCROLL, X, 8, W, 380, hMain, idTglList),
		mkCtl("EDIT", "ENTITY", WS_CHILD|WS_BORDER, X, 396, 200, 26, hMain, idTglEdit),
		mkCtl("BUTTON", "Вкл/Выкл", WS_CHILD, X+208, 394, 120, 28, hMain, idTglBtn),
	}
	pages[3] = []uintptr{
		mkCtl("EDIT", "", WS_CHILD|WS_BORDER|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY, X, 8, W, 420, hMain, idAuditOut),
		mkCtl("BUTTON", "Обновить", WS_CHILD, X, 434, 120, 28, hMain, idAuditBtn),
	}
	hLoading = mkCtl("STATIC", "sentinel — загрузка…", WS_CHILD|WS_VISIBLE|SS_CENTER, 168, 200, 588, 60, hMain, 0)
	setContentVisible(false)
	trace("loading shown")
	pSetTimer.Call(hMain, 1, 3000, 0)
	loadStartMs = tickMs()
	loadDataAsync(hMain)
	go hungWatchdog(hMain)
	trace("async started")
	trace("loop enter")
	var m struct {
		hwnd    uintptr
		message uint32
		_       uint32
		w, l    uintptr
		time    uint32
		pt      [2]int32
		_       uint32
	}
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if r == 0 {
			break
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}
