package Core

import (
	"context"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var fingerprintSem *semaphore.Weighted // This is already here

// Define the new struct for results and logs
type ResultLogItem struct {
    Result     *Common.ScanResult
    LogMessage string
    IsErrorLog bool // Though current usage is for LogInfo, future might use it for errors
}

// EnhancedPortScan 高性能端口扫描函数
func EnhancedPortScan(hosts []string, ports string, timeout int64) []string {
	fingerprintSem = semaphore.NewWeighted(int64(50))
	portList := Common.ParsePort(ports)
	if len(portList) == 0 {
		Common.LogError("无效端口: " + ports) // This LogError can remain direct
		return nil
	}

	exclude := make(map[int]struct{})
	for _, p := range Common.ParsePort(Common.ExcludePorts) {
		exclude[p] = struct{}{}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	to := time.Duration(timeout) * time.Second
	sem := semaphore.NewWeighted(int64(Common.ThreadNum))
	var count int64
	var aliveMap sync.Map // This is for the final return list, keep it.
	g, ctx := errgroup.WithContext(ctx)

    // 1. Define result channel
    resultsChan := make(chan ResultLogItem, 200) // Use the new struct

    // 2. Start result processing goroutine
    var resultWg sync.WaitGroup
    resultWg.Add(1)
    go func() {
        defer resultWg.Done()
        for item := range resultsChan {
            if item.Result != nil {
                Common.SaveResult(item.Result)
            }
            if item.LogMessage != "" {
                // Assuming IsErrorLog is false for these specific logs as per current direct calls
                // if item.IsErrorLog { Common.LogError(item.LogMessage) } else { Common.LogInfo(item.LogMessage) }
                Common.LogInfo(item.LogMessage)
            }
        }
    }()

	// Main scanning loop (for _, host := range hosts)
	for _, hostLoopVar := range hosts {
		for _, portLoopVar := range portList {
			if _, excluded := exclude[portLoopVar]; excluded {
				continue
			}

            // Capture loop variables for goroutine
            currentHost := hostLoopVar
            currentPort := portLoopVar
            currentAddr := fmt.Sprintf("%s:%d", currentHost, currentPort)

			if err := sem.Acquire(ctx, 1); err != nil {
                // Error acquiring semaphore, break the inner loop for this host
                Common.LogError(fmt.Sprintf("Failed to acquire semaphore for %s: %v", currentAddr, err))
                break 
            }

			g.Go(func() error {
				defer sem.Release(1)

				conn, err := net.DialTimeout("tcp", currentAddr, to)
				if err != nil {
					return nil // Error handled by not proceeding
				}
				defer conn.Close()

				atomic.AddInt64(&count, 1)
				aliveMap.Store(currentAddr, struct{}{}) // Keep aliveMap for return value

                // 3. Modify scanning goroutines to send to resultsChan
                portOpenLogMsg := fmt.Sprintf("端口开放 %s", currentAddr)
                resultsChan <- ResultLogItem{
                    Result: &Common.ScanResult{
                        Time:   time.Now(),
                        Type:   Common.PORT,
                        Target: currentHost, 
                        Status: "open",
                        Details: map[string]interface{}{"port": currentPort}, 
                    },
                    LogMessage: portOpenLogMsg,
                    IsErrorLog: false,
                }

				if Common.EnableFingerprint {
					if err := fingerprintSem.Acquire(ctx, 1); err != nil {
                        Common.LogError(fmt.Sprintf("Fingerprint scan skipped for %s:%d due to semaphore acquisition failure: %v", currentHost, currentPort, err))
					} else {
						defer fingerprintSem.Release(1)
						if info, err := NewPortInfoScanner(currentHost, currentPort, conn, to).Identify(); err == nil {
                            details := map[string]interface{}{"port": currentPort, "service": info.Name}
                            if info.Version != "" { details["version"] = info.Version }
                            for k, v := range info.Extras {
                                if v == "" { continue }
                                switch k {
                                case "vendor_product": details["product"] = v
                                case "os", "info": details[k] = v
                                }
                            }
                            if len(info.Banner) > 0 { details["banner"] = strings.TrimSpace(info.Banner) }

                            var sb strings.Builder
                            sb.WriteString(fmt.Sprintf("服务识别 %s => ", currentAddr))
                            if info.Name != "unknown" { sb.WriteString("[" + info.Name + "]") }
                            if info.Version != "" { sb.WriteString(" 版本:" + info.Version) }
                            for k, v := range info.Extras {
                                if v == "" { continue }
                                switch k {
                                case "vendor_product": sb.WriteString(" 产品:" + v)
                                case "os": sb.WriteString(" 系统:" + v)
                                case "info": sb.WriteString(" 信息:" + v)
                                }
                            }
                            if len(info.Banner) > 0 && len(info.Banner) < 100 {
                                sb.WriteString(" Banner:[" + strings.TrimSpace(info.Banner) + "]")
                            }
                            serviceLogMsg := sb.String()

                            resultsChan <- ResultLogItem{
                                Result: &Common.ScanResult{
                                    Time:   time.Now(),
                                    Type:   Common.SERVICE,
                                    Target: currentHost, 
                                    Status: "identified",
                                    Details: details,
                                },
                                LogMessage: serviceLogMsg,
                                IsErrorLog: false,
                            }
						}
					}
				}
				return nil
			}) // End of g.Go
		} // End of port loop
	} // End of host loop

	if err := g.Wait(); err != nil {
        // Log error from errgroup if any non-nil error is returned by a goroutine
        Common.LogError(fmt.Sprintf("Error during port scanning: %v", err))
    }

    // 4. Ensure proper shutdown
    close(resultsChan)
    resultWg.Wait()

	var aliveAddrs []string
	aliveMap.Range(func(key, _ interface{}) bool {
		aliveAddrs = append(aliveAddrs, key.(string))
		return true
	})

	Common.LogBase(fmt.Sprintf("扫描完成, 发现 %d 个开放端口", count)) // This LogBase can remain direct
	return aliveAddrs
}
