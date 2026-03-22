package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var modeName string

// Shared HTTP client with proper connection pooling
var httpClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:        10000,
		MaxIdleConnsPerHost: 10000,
		MaxConnsPerHost:     10000,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
	},
	Timeout: 30 * time.Second,
}

type tokenRequest struct {
	AgentID    string `json:"agent_id"`
	IntentHash string `json:"intent_hash"`
	ActionType string `json:"action_type"`
}

type result struct {
	latency time.Duration
	ok      bool
}

type stats struct {
	concurrency int
	totalReqs   int64
	successReqs int64
	duration    time.Duration
	p50         time.Duration
	p95         time.Duration
	p99         time.Duration
	rps         float64
}

func main() {
	baseURL := os.Getenv("KERNEL_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	concurrencyLevels := []int{10, 100, 500, 1000, 5000}
	testDuration := 10 * time.Second
	runsPerLevel := 3

	modeName = os.Getenv("VAOS_KERNEL_MODE")
	if modeName == "" {
		modeName = "sync"
	}

	fmt.Println("vaos-kernel benchmark")
	fmt.Printf("Target: %s/api/token\n", baseURL)
	fmt.Printf("Mode: %s\n", modeName)
	fmt.Printf("Duration per run: %v, Runs per level: %d\n\n", testDuration, runsPerLevel)

	// Determine endpoint based on mode
	_ = modeName // used in benchmark goroutines

	// Warm up
	fmt.Print("Warming up... ")
	for i := 0; i < 100; i++ {
		if modeName == "baseline" {
			sendHealthRequest(baseURL)
		} else {
			sendRequest(baseURL, i)
		}
	}
	fmt.Println("done")

	allStats := make([]stats, 0)

	for _, concurrency := range concurrencyLevels {
		var runStats []stats
		for run := 0; run < runsPerLevel; run++ {
			s := benchmark(baseURL, concurrency, testDuration)
			runStats = append(runStats, s)
			fmt.Printf("  Run %d/%d: %d RPS, p50=%.2fms p95=%.2fms p99=%.2fms\n",
				run+1, runsPerLevel, int(s.rps),
				float64(s.p50.Microseconds())/1000,
				float64(s.p95.Microseconds())/1000,
				float64(s.p99.Microseconds())/1000)
		}

		// Average across runs
		avg := averageStats(runStats, concurrency)
		allStats = append(allStats, avg)

		fmt.Printf("  AVG c=%d: %.0f RPS, p50=%.2fms p95=%.2fms p99=%.2fms (%d/%d ok)\n\n",
			concurrency, avg.rps,
			float64(avg.p50.Microseconds())/1000,
			float64(avg.p95.Microseconds())/1000,
			float64(avg.p99.Microseconds())/1000,
			avg.successReqs, avg.totalReqs)
	}

	// Output CSV
	csvPath := fmt.Sprintf("benchmark_%s.csv", modeName)
	f, _ := os.Create(csvPath)
	defer f.Close()
	fmt.Fprintln(f, "concurrency,rps,p50_ms,p95_ms,p99_ms,total,success")
	for _, s := range allStats {
		fmt.Fprintf(f, "%d,%.2f,%.3f,%.3f,%.3f,%d,%d\n",
			s.concurrency, s.rps,
			float64(s.p50.Microseconds())/1000,
			float64(s.p95.Microseconds())/1000,
			float64(s.p99.Microseconds())/1000,
			s.totalReqs, s.successReqs)
	}
	fmt.Printf("Results saved to %s\n", csvPath)

	// Output JSON for paper pipeline
	jsonPath := fmt.Sprintf("benchmark_%s.json", modeName)
	jf, _ := os.Create(jsonPath)
	defer jf.Close()
	json.NewEncoder(jf).Encode(map[string]interface{}{
		"hardware": map[string]string{
			"machine":  "Apple Mac Mini M4",
			"cpu":      "10-core",
			"ram":      "16GB",
			"storage":  "512GB NVMe SSD",
			"go":       "1.26.1",
			"postgres": "local",
		},
		"config": map[string]interface{}{
			"duration_sec":   testDuration.Seconds(),
			"runs_per_level": runsPerLevel,
			"mode":           modeName,
		},
		"results": allStats,
	})
	fmt.Printf("JSON saved to %s\n", jsonPath)
}

func benchmark(baseURL string, concurrency int, duration time.Duration) stats {
	var (
		total   int64
		success int64
		results []result
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	done := make(chan struct{})
	go func() {
		time.Sleep(duration)
		close(done)
	}()

	// Poisson-distributed arrivals per goroutine
	lambda := 100.0 // target requests per second per goroutine
	if concurrency > 100 {
		lambda = 50.0
	}
	if concurrency > 1000 {
		lambda = 20.0
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))

			for {
				select {
				case <-done:
					return
				default:
				}

				// Poisson inter-arrival time
				sleepMs := -math.Log(1-rng.Float64()) / lambda * 1000
				time.Sleep(time.Duration(sleepMs) * time.Millisecond)

				start := time.Now()
				var ok bool
				if modeName == "baseline" {
					ok = sendHealthRequest(baseURL)
					atomic.AddInt64(&total, 1)
				} else {
					ok = sendRequest(baseURL, int(atomic.AddInt64(&total, 1)))
				}
				elapsed := time.Since(start)

				if ok {
					atomic.AddInt64(&success, 1)
				}

				mu.Lock()
				results = append(results, result{latency: elapsed, ok: ok})
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	// Calculate percentiles
	latencies := make([]time.Duration, len(results))
	for i, r := range results {
		latencies[i] = r.latency
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	n := len(latencies)
	if n == 0 {
		return stats{concurrency: concurrency}
	}

	return stats{
		concurrency: concurrency,
		totalReqs:   total,
		successReqs: success,
		duration:    duration,
		p50:         latencies[n*50/100],
		p95:         latencies[n*95/100],
		p99:         latencies[n*99/100],
		rps:         float64(total) / duration.Seconds(),
	}
}

func sendRequest(baseURL string, nonce int) bool {
	agents := []string{"bootstrap-agent", "zoe", "osa"}
	agent := agents[nonce%len(agents)]

	req := tokenRequest{
		AgentID:    agent,
		IntentHash: fmt.Sprintf("bench-%d-%d", nonce, time.Now().UnixNano()),
		ActionType: "benchmark",
	}

	body, _ := json.Marshal(req)
	resp, err := httpClient.Post(baseURL+"/api/token", "application/json", bytes.NewReader(body))
	if err != nil {
		return false
	}
	// Drain body to enable connection reuse
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode == 200
}

func sendHealthRequest(baseURL string) bool {
	resp, err := httpClient.Get(baseURL + "/health")
	if err != nil {
		return false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode == 200
}

func averageStats(runs []stats, concurrency int) stats {
	var totalRPS float64
	var totalP50, totalP95, totalP99 time.Duration
	var totalReqs, totalSuccess int64

	for _, r := range runs {
		totalRPS += r.rps
		totalP50 += r.p50
		totalP95 += r.p95
		totalP99 += r.p99
		totalReqs += r.totalReqs
		totalSuccess += r.successReqs
	}

	n := len(runs)
	return stats{
		concurrency: concurrency,
		totalReqs:   totalReqs / int64(n),
		successReqs: totalSuccess / int64(n),
		duration:    runs[0].duration,
		p50:         totalP50 / time.Duration(n),
		p95:         totalP95 / time.Duration(n),
		p99:         totalP99 / time.Duration(n),
		rps:         totalRPS / float64(n),
	}
}
