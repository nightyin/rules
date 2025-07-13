package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var (
	// ||example.com^ 或 ||example.com$dnsrewrite= 之类
	reSuffix = regexp.MustCompile(`^\|\|([a-z0-9.-]+)[\^$]`)
	// |http://example.com/path 只取 host
	reExact = regexp.MustCompile(`^\|https?://([^/^]+)`)
	// example.com^
	rePlain = regexp.MustCompile(`^([a-z0-9.-]+)\^?$`)
)

func main() {
	url := "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	out, _ := os.Create("adguard-dns-surge.txt")
	defer out.Close()
	w := bufio.NewWriter(out)
	defer w.Flush()

	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(resp.Body)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@@") {
			continue // 注释、空行、白名单跳过
		}

		domain := ""
		switch {
		case reSuffix.MatchString(line):
			domain = reSuffix.FindStringSubmatch(line)[1]
		case reExact.MatchString(line):
			domain = reExact.FindStringSubmatch(line)[1]
		case rePlain.MatchString(line):
			domain = rePlain.FindStringSubmatch(line)[1]
		}

		if domain == "" || strings.Contains(domain, "*") {
			continue // 复杂 wildcard 暂不处理
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		fmt.Fprintf(w, ".%s\n", domain) // DOMAIN-SET 格式：前缀一个点表示含子域
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}
	fmt.Println("✅ 生成完成 adguard-dns-surge.txt")
}
