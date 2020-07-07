package http

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime/pprof"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/myntra/golimit/store"
	"github.com/patrickmn/go-cache"
	"github.com/pressly/chi"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

type HttpServer struct {
	port          int
	hostname      string
	unixSocksFile string
	router        *chi.Mux
	store         *store.Store
}

func NewGoHttpServer(port int, hostname string, store *store.Store) *HttpServer {
	server := &HttpServer{port: port, hostname: hostname, store: store}
	server.router = chi.NewRouter()
	server.registerHttpHandlers()
	server.uiHandler()
	go http.ListenAndServe(":"+strconv.Itoa(port), server.router)
	log.Infof("http server started on port %d", port)
	return server
}

func NewGoHttpServerOnUnixSocket(sockFile string, store *store.Store) *HttpServer {
	server := &HttpServer{unixSocksFile: sockFile, store: store}
	server.router = chi.NewRouter()
	server.registerHttpHandlers()
	listener, err := net.Listen("unix", sockFile)
	if err != nil {
		log.Error(err)
		return nil
	}
	go http.Serve(listener, server.router)
	log.Infof("http server started on socket %s", sockFile)
	return server
}

func (s *HttpServer) registerHttpHandlers() {

	s.router.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pong"))
	})

	s.router.Post("/incr", func(w http.ResponseWriter, r *http.Request) {
		var countStr, windowStr, thresholdStr, peakBust string

		key := r.URL.Query().Get("K")
		if r.URL.Query().Get("C") != "" {
			countStr = r.URL.Query().Get("C")
		} else {
			countStr = "1"
		}

		thresholdStr = r.URL.Query().Get("T")
		windowStr = r.URL.Query().Get("W")
		peakBust = r.URL.Query().Get("P")

		count, err := strconv.Atoi(countStr)
		if err != nil {
			http.Error(w, "Count should be numeric", 400)
			return
		}

		threshold, err := strconv.Atoi(thresholdStr)
		if err != nil {
			http.Error(w, "Threshold should be numeric", 400)
			return
		}
		window, err := strconv.Atoi(windowStr)
		if err != nil {
			http.Error(w, "Window should be numeric", 400)
			return
		}
		peakaveraged, err := strconv.Atoi(peakBust)
		if err != nil {
			peakaveraged = 0
		}

		ret := s.store.Incr(key, int32(count), int32(threshold), int32(window), peakaveraged > 0)
		w.Header().Set("Content-Type", "application/json")
		w.Write((serialize(struct{ Block bool }{Block: ret})))

	})

	s.router.Post("/ratelimit", func(w http.ResponseWriter, r *http.Request) {
		var countStr string
		key := r.URL.Query().Get("K")
		if r.URL.Query().Get("C") != "" {
			countStr = r.URL.Query().Get("C")
		} else {
			countStr = "1"
		}

		count, err := strconv.Atoi(countStr)
		if err != nil {
			http.Error(w, "Count should be numeric", 400)
			return
		}
		ret := s.store.RateLimitGlobal(key, int32(count))
		w.Header().Set("Content-Type", "application/json")
		w.Write((serialize(struct{ Block bool }{Block: ret})))

	})

	s.router.Post("/shield/*", func(w http.ResponseWriter, r *http.Request) {
		var countStr string

		path := chi.URLParam(r, "*")
		url, _ := url.Parse("http://demo-app:8090/" + path)
		if s.store.GetRateConfig(path) != nil {
			searchKey := "site.publisher.id"
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				log.Printf("Error reading body: %v", err)
				http.Error(w, "can't read body", http.StatusBadRequest)
				return
			}
			pID := gjson.Get(string(body), searchKey).String()

			keyPrefix := strings.Join([]string{path, "^", searchKey, "|"}, "")

			log.Debug("Key parsed: %s", keyPrefix+pID)

			keys := [1]string{strings.Join([]string{keyPrefix, pID}, "")}
			if r.URL.Query().Get("C") != "" {
				countStr = r.URL.Query().Get("C")
			} else {
				countStr = "1"
			}

			count, err := strconv.Atoi(countStr)
			if err != nil {
				http.Error(w, "Count should be numeric", 400)
				return
			}
			retFinal := false
			for _, key := range keys {
				globalKey := keyPrefix + "*"
				log.Debug("Global Key parsed: %s", globalKey)
				if s.store.GetRateConfig(key) == nil && s.store.GetRateConfig(globalKey) != nil {
					log.Info("Key Not found: " + key + ", using global config for key:" + globalKey)
					newRateConfig := s.store.GetRateConfig(globalKey)
					s.store.SetRateConfig(key,
						store.RateConfig{
							Limit:        int32(newRateConfig.Limit),
							Window:       int32(newRateConfig.Window),
							PeakAveraged: newRateConfig.PeakAveraged,
							Source:       "wildcard-" + globalKey})
				}
				ret := s.store.RateLimitGlobal(key, int32(count))
				if ret == true {
					log.Debug("Rate Limit Hit for key: %s", key)
					retFinal = true
				}
			}

			//Recreate request body
			if retFinal == false {
				r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
				proxy := getCustomHostReverseProxy(url, 5) //httputil.NewSingleHostReverseProxy(url)
				proxy.ServeHTTP(w, r)
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.Write((serialize(struct{ Block bool }{Block: retFinal})))
			}
		} else {
			log.Debug("No Rate config found for path: %s", path)
			proxy := getCustomHostReverseProxy(url, 5)
			proxy.ServeHTTP(w, r)
		}

	})

	s.router.Get("/shield/*", func(w http.ResponseWriter, r *http.Request) {
		var countStr string
		keys := strings.Split(r.URL.Query().Get("K"), ",")
		if r.URL.Query().Get("C") != "" {
			countStr = r.URL.Query().Get("C")
		} else {
			countStr = "1"
		}

		count, err := strconv.Atoi(countStr)
		if err != nil {
			http.Error(w, "Count should be numeric", 400)
			return
		}
		retFinal := true
		for _, key := range keys {
			ret := s.store.RateLimitGlobal(key, int32(count))
			if ret == false {
				retFinal = false
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write((serialize(struct{ Block bool }{Block: retFinal})))

	})

	s.router.Get("/rateall", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write((serialize(s.store.GetRateConfigAll())))
	})

	s.router.Get("/rate", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("K")
		if s.store.GetRateConfig(key) == nil {
			http.Error(w, "Key Not found", 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write((serialize(s.store.GetRateConfig(key))))
	})

	s.router.Get("/clusterinfo", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")
		w.Write((serialize(s.store.GetClusterInfo())))
	})

	s.router.Put("/rate", func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		secret := r.Header.Get("apisecret")
		if !s.store.IsAuthorised(secret) {
			http.Error(w, "Invalid Api Secret", 403)
			return
		}
		rate := struct {
			Key             string
			Window          int
			Limit           int
			PeakAveraged    bool
			DefaultResponse string
			DefaultHeaders  string
			Source          string
		}{}
		decoder.Decode(&rate)
		log.Info("RateConfig Update request %+v", rate)
		if strings.TrimSpace(rate.Key) == "" || rate.Window < 1 || rate.Limit < 1 {
			http.Error(w, "Invalid Rate Config", 400)
			return
		}

		if strings.Contains(strings.TrimSpace(rate.Key), "*") {
			rate.Source = "wildcard"
			//Get and Update/delete all child rates
		}

		s.store.SetRateConfig(rate.Key, store.RateConfig{Limit: int32(rate.Limit), Window: int32(rate.Window),
			PeakAveraged: rate.PeakAveraged, DefaultResponse: rate.DefaultResponse, DefaultHeaders: rate.DefaultHeaders})

		w.Header().Set("Content-Type", "application/json")
		w.Write(serialize(struct{ Success bool }{Success: true}))
	})

	s.router.Get("/profilecpuenable", func(w http.ResponseWriter, r *http.Request) {

		secret := r.Header.Get("apisecret")
		if !s.store.IsAuthorised(secret) {
			http.Error(w, "Invalid Api Secret", 403)
			return
		}
		f, err := os.Create("golimitV3_cpu.pprof")
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		w.Header().Set("Content-Type", "application/json")
		w.Write(serialize(struct{ Success bool }{Success: true}))
	})
	s.router.Get("/profilecpudisable", func(w http.ResponseWriter, r *http.Request) {

		secret := r.Header.Get("apisecret")
		if !s.store.IsAuthorised(secret) {
			http.Error(w, "Invalid Api Secret", 403)
			return
		}
		pprof.StopCPUProfile()
		w.Header().Set("Content-Type", "application/json")
		w.Write(serialize(struct{ Success bool }{Success: true}))
	})

	s.router.Get("/memprofile", func(w http.ResponseWriter, r *http.Request) {

		secret := r.Header.Get("apisecret")
		if !s.store.IsAuthorised(secret) {
			http.Error(w, "Invalid Api Secret", 403)
			return
		}
		f, err := os.Create("golimitV3_mem.pprof")
		if err != nil {
			log.Fatal(err)
		}
		pprof.WriteHeapProfile(f)
		f.Close()
		w.Header().Set("Content-Type", "application/json")
		w.Write(serialize(struct{ Success bool }{Success: true}))
	})

}

func serialize(obj interface{}) []byte {

	if str, err := json.Marshal(obj); err != nil {
		log.Errorf("Error serializing +%v", obj)
		return nil
	} else {
		return str
	}

}

func (s *HttpServer) uiHandler() {

	basePath := "/ui/"
	dir, _ := os.Getwd()

	tmpl := template.Must(template.ParseFiles(dir + "/" + basePath + "index.html"))
	// configure static file path
	staticPath := basePath + "lib/"

	fileServer(s.router, staticPath, http.Dir("./"+staticPath))
	s.router.HandleFunc("/ui", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			tmpl.Execute(w, nil)
			return
		}
	})
}

// FileServer conveniently sets up a http.FileServer handler to serve
// static files from a http.FileSystem.
func fileServer(r chi.Router, path string, root http.FileSystem) {
	if strings.ContainsAny(path, "{}*") {
		panic("FileServer does not permit any URL parameters.")
	}

	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", 301).ServeHTTP)
		path += "/"
	}
	path += "*"

	r.Get(path, func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		fs := http.StripPrefix(pathPrefix, http.FileServer(root))
		fs.ServeHTTP(w, r)
	})
var Cache = cache.New(5*time.Minute, 5*time.Minute)

func GetCache(key string) (*httputil.ReverseProxy, bool) {
	var rp *httputil.ReverseProxy
	var found bool
	data, found := Cache.Get(key)
	if found {
		rp = data.(*httputil.ReverseProxy)
	}
	return rp, found
}

func SetCache(key string, rp *httputil.ReverseProxy) bool {
	Cache.Set(key, rp, cache.NoExpiration)
	return true
}

func getCustomHostReverseProxy(target *url.URL, timeout int64) *httputil.ReverseProxy {

	var rp, found = GetCache(target.Path)
	if found {
		return rp
	}
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host

		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
	}

	var newRp = &httputil.ReverseProxy{
		Director: director,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   2000 * time.Millisecond,
				KeepAlive: 300 * time.Second,
				//Deadline:  time.Now().Add(time.Duration(timeout) * time.Millisecond),
				DualStack: true,
			}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	SetCache(target.Path, newRp)
	return newRp
}
