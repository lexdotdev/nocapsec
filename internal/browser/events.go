package browser

import (
	"context"
	"net/url"
	"sync"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// eventCollector records CDP events during a browser job.
type eventCollector struct {
	mu      sync.Mutex
	navs    []NavEvent
	dialogs []DialogEvent
	console []ConsoleEvent
	netEvts []NetEvent
}

// attach registers CDP event listeners on the chromedp context.
func (ec *eventCollector) attach(ctx context.Context) {
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *page.EventJavascriptDialogOpening:
			ec.recordDialog(e)
			go func() {
				// Auto-accept so the page cannot block execution.
				_ = chromedp.Run(ctx, page.HandleJavaScriptDialog(true))
			}()

		case *runtime.EventConsoleAPICalled:
			ec.recordConsole(e)

		case *page.EventFrameNavigated:
			ec.recordNav(e)

		case *network.EventRequestWillBeSent:
			ec.recordNet(e)
		}
	})
}

func (ec *eventCollector) recordDialog(e *page.EventJavascriptDialogOpening) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.dialogs = append(ec.dialogs, DialogEvent{
		Type:         e.Type.String(),
		Message:      e.Message,
		SourceOrigin: originFromFrameURL(e.URL),
	})
}

func (ec *eventCollector) recordConsole(e *runtime.EventConsoleAPICalled) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	text := ""
	for _, arg := range e.Args {
		if arg.Value != nil {
			text += string(arg.Value)
		}
	}
	sourceURL := ""
	if e.StackTrace != nil && len(e.StackTrace.CallFrames) > 0 {
		sourceURL = e.StackTrace.CallFrames[0].URL
	}
	ec.console = append(ec.console, ConsoleEvent{
		Text:      text,
		SourceURL: sourceURL,
	})
}

func (ec *eventCollector) recordNav(e *page.EventFrameNavigated) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.navs = append(ec.navs, NavEvent{
		URL:    e.Frame.URL,
		Origin: originFromFrameURL(e.Frame.URL),
	})
}

func (ec *eventCollector) recordNet(e *network.EventRequestWillBeSent) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.netEvts = append(ec.netEvts, NetEvent{
		URL:    e.Request.URL,
		Method: e.Request.Method,
	})
}

// snapshot returns copies of all collected events.
func (ec *eventCollector) snapshot() ([]NavEvent, []DialogEvent, []ConsoleEvent, []NetEvent) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	navs := make([]NavEvent, len(ec.navs))
	copy(navs, ec.navs)
	dialogs := make([]DialogEvent, len(ec.dialogs))
	copy(dialogs, ec.dialogs)
	console := make([]ConsoleEvent, len(ec.console))
	copy(console, ec.console)
	netEvts := make([]NetEvent, len(ec.netEvts))
	copy(netEvts, ec.netEvts)
	return navs, dialogs, console, netEvts
}

// originFromFrameURL extracts origin from a URL string.
func originFromFrameURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Scheme + "://" + u.Host
}
