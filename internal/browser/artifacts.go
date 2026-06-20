package browser

import (
	"context"

	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/chromedp"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
)

// captureArtifacts grabs screenshot + DOM,
// only on proof.
func captureArtifacts(ctx context.Context, store artifacts.ArtifactStore, jobID string) (screenshotRef, domRef string) {
	if store == nil {
		return "", ""
	}

	var png []byte
	if err := chromedp.Run(ctx, chromedp.CaptureScreenshot(&png)); err == nil && len(png) > 0 {
		if ref, err := store.Put(ctx, jobID, artifacts.KindScreenshot, png); err == nil {
			screenshotRef = ref
		}
	}

	var html string
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		node, err := dom.GetDocument().Do(ctx)
		if err != nil {
			return err
		}
		html, err = dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)
		return err
	})); err == nil && html != "" {
		if ref, err := store.Put(ctx, jobID, artifacts.KindDOMSnapshot, []byte(html)); err == nil {
			domRef = ref
		}
	}

	return screenshotRef, domRef
}
