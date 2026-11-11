package truststore

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ca-chain-check/assets"
)

func TestRetryDelay(t *testing.T) {
	min, max := time.Minute, time.Hour
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour}
	for i, w := range want {
		if got := RetryDelay(i+1, min, max); got != w {
			t.Errorf("retry %d: %v, want %v", i+1, got, w)
		}
	}
}

func embedded() Sources {
	return Sources{MozillaPEM: assets.MozillaRootsPEM, StoresCSV: assets.RootStoresCSV, MicrosoftCSV: assets.MicrosoftRootsCSV}
}

// ccadb serves the embedded reports, failing the first `fail` requests.
func ccadb(t *testing.T, fail int32) (*httptest.Server, *atomic.Int32) {
	var n atomic.Int32
	src := embedded()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= fail {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/mozilla":
			w.Write(src.MozillaPEM)
		case "/stores":
			w.Write(src.StoresCSV)
		case "/microsoft":
			w.Write(src.MicrosoftCSV)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func loader(url string, fallback Sources) *Loader {
	return &Loader{
		MozillaURL: url + "/mozilla", StoresURL: url + "/stores", MicrosoftURL: url + "/microsoft",
		Fallback: fallback, FallbackDate: time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC),
		RetryMin: 10 * time.Millisecond, RetryMax: 40 * time.Millisecond,
	}
}

// A failed first download keeps the embedded copy, reports the failure and
// retries soon instead of waiting a full interval.
func TestLoaderRetriesAfterFailure(t *testing.T) {
	srv, _ := ccadb(t, 3)
	l := loader(srv.URL, embedded())
	err := l.Init(context.Background())
	if err == nil {
		t.Fatal("first download should fail")
	}
	if info := l.Store.Info(); info.Source != "embedded snapshot" || info.Count == 0 || !info.LoadedAt.Equal(l.FallbackDate) {
		t.Fatalf("after failed init: %+v", info)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go l.Run(ctx, time.Hour, err)
	deadline := time.Now().Add(5 * time.Second)
	sawFailing := false
	for time.Now().Before(deadline) {
		info := l.Store.Info()
		if info.RefreshFailing && info.NextAttempt != nil {
			sawFailing = true
		}
		if info.Source == "CCADB" && !info.RefreshFailing && info.NextAttempt == nil {
			if !sawFailing {
				t.Error("never reported the failing download")
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("never recovered: %+v", l.Store.Info())
}

// With no usable embedded copy and no download, the store is empty.
func TestLoaderEmptyWithoutData(t *testing.T) {
	srv, _ := ccadb(t, 1<<30)
	l := loader(srv.URL, Sources{})
	if err := l.Init(context.Background()); err == nil {
		t.Fatal("download should fail")
	}
	if !l.Store.Empty() {
		t.Fatal("store should be empty")
	}
	if err := l.Refresh(context.Background()); err == nil {
		t.Fatal("refresh should keep failing")
	}
}

// Cross-signs come from the embedded copy until the intermediate report
// downloads; a failed download of that report keeps them and does not fail
// the refresh.
func TestLoaderCrossSigns(t *testing.T) {
	src := embedded()
	src.CrossSignsPEM = assets.CrossSignsPEM
	var interOK atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mozilla":
			w.Write(src.MozillaPEM)
		case "/stores":
			w.Write(src.StoresCSV)
		case "/microsoft":
			w.Write(src.MicrosoftCSV)
		case "/intermediates":
			if !interOK.Load() {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			// One cross-sign from the embedded copy, as the CSV report
			// quotes it.
			c := ParsePEMBundle(src.CrossSignsPEM)[0]
			p := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})))
			fmt.Fprintf(w, "\"Certificate Name\",\"PEM Info\"\n\"x\",\"'%s'\"\n", p)
		}
	}))
	defer srv.Close()
	l := loader(srv.URL, src)
	l.IntermediatesURL = srv.URL + "/intermediates"
	want := len(ParsePEMBundle(src.CrossSignsPEM))
	if want < 50 {
		t.Fatalf("embedded cross-signs: %d", want)
	}
	if err := l.Init(context.Background()); err != nil {
		t.Fatalf("a failed intermediate download must not fail the refresh: %v", err)
	}
	if info := l.Store.Info(); info.Source != "CCADB" || info.CrossSigns != want {
		t.Fatalf("after failed intermediate download: source %s, %d cross-signs, want %d", info.Source, info.CrossSigns, want)
	}
	interOK.Store(true)
	if err := l.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := l.Store.Info().CrossSigns; n != 1 {
		t.Errorf("after download: %d cross-signs, want 1", n)
	}
}
