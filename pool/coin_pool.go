package pool

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// defaultMainstreamCoins 默认主流币种池（从配置文件读取）
var defaultMainstreamCoins = []string{
	"BTCUSDT",
	"ETHUSDT",
	"SOLUSDT",
	"BNBUSDT",
	"XRPUSDT",
	"DOGEUSDT",
	"ADAUSDT",
	"HYPEUSDT",
}

// CoinPoolConfig 币种池配置
type CoinPoolConfig struct {
	APIURL          string
	Timeout         time.Duration
	CacheDir        string
	UseDefaultCoins bool // 是否使用默认主流币种
}

var coinPoolConfig = CoinPoolConfig{
	APIURL:          "",
	Timeout:         30 * time.Second, // 增加到30秒
	CacheDir:        "coin_pool_cache",
	UseDefaultCoins: false, // 默认不使用
}

// CoinPoolCache 币种池缓存
type CoinPoolCache struct {
	Coins      []CoinInfo `json:"coins"`
	FetchedAt  time.Time  `json:"fetched_at"`
	SourceType string     `json:"source_type"` // "api" or "cache"
}

// CoinInfo 币种信息
type CoinInfo struct {
	Pair            string  `json:"pair"`             // 交易对符号（例如：BTCUSDT）
	Score           float64 `json:"score"`            // 当前评分
	StartTime       int64   `json:"start_time"`       // 开始时间（Unix时间戳）
	StartPrice      float64 `json:"start_price"`      // 开始价格
	LastScore       float64 `json:"last_score"`       // 最新评分
	MaxScore        float64 `json:"max_score"`        // 最高评分
	MaxPrice        float64 `json:"max_price"`        // 最高价格
	IncreasePercent float64 `json:"increase_percent"` // 涨幅百分比
	IsAvailable     bool    `json:"-"`                // 是否可交易（内部使用）
}

// CoinPoolAPIResponse API返回的原始数据结构
type CoinPoolAPIResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Coins []CoinInfo `json:"coins"`
		Count int        `json:"count"`
	} `json:"data"`
}

// SetCoinPoolAPI 设置币种池API
func SetCoinPoolAPI(apiURL string) {
	coinPoolConfig.APIURL = apiURL
}

// SetOITopAPI 设置OI Top API
func SetOITopAPI(apiURL string) {
	trimmed := strings.TrimSpace(apiURL)
	if trimmed == "" || strings.EqualFold(trimmed, "binance") {
		oiTopConfig.APIURL = defaultBinanceOpenInterestURL
		oiTopConfig.Provider = "binance"
		log.Printf("✓ 已启用币安官方持仓量API: %s", oiTopConfig.APIURL)
		return
	}

	if strings.EqualFold(trimmed, "none") || strings.EqualFold(trimmed, "disable") || strings.EqualFold(trimmed, "disabled") {
		oiTopConfig.APIURL = ""
		oiTopConfig.Provider = "disabled"
		log.Printf("⚠️  已禁用OI Top数据源")
		return
	}

	if strings.Contains(strings.ToLower(trimmed), "binance.com") {
		oiTopConfig.APIURL = trimmed
		oiTopConfig.Provider = "binance"
		log.Printf("✓ 已启用币安官方持仓量API: %s", oiTopConfig.APIURL)
		return
	}

	oiTopConfig.APIURL = trimmed
	oiTopConfig.Provider = "custom"
	log.Printf("✓ 已配置自定义OI Top API: %s", oiTopConfig.APIURL)
}

// SetUseDefaultCoins 设置是否使用默认主流币种
func SetUseDefaultCoins(useDefault bool) {
	coinPoolConfig.UseDefaultCoins = useDefault
}

// SetDefaultCoins 设置默认主流币种列表
func SetDefaultCoins(coins []string) {
	if len(coins) > 0 {
		defaultMainstreamCoins = coins
		log.Printf("✓ 已设置默认币种池（共%d个币种）: %v", len(coins), coins)
	}
}

// GetCoinPool 获取币种池列表（带重试和缓存机制）
func GetCoinPool() ([]CoinInfo, error) {
	// 优先检查是否启用默认币种列表
	if coinPoolConfig.UseDefaultCoins {
		log.Printf("✓ 已启用默认主流币种列表")
		return convertSymbolsToCoins(defaultMainstreamCoins), nil
	}

	// 检查API URL是否配置
	if strings.TrimSpace(coinPoolConfig.APIURL) == "" {
		log.Printf("⚠️  未配置币种池API URL，使用默认主流币种列表")
		return convertSymbolsToCoins(defaultMainstreamCoins), nil
	}

	maxRetries := 3
	var lastErr error

	// 尝试从API获取
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			log.Printf("⚠️  第%d次重试获取币种池（共%d次）...", attempt, maxRetries)
			time.Sleep(2 * time.Second) // 重试前等待2秒
		}

		coins, err := fetchCoinPool()
		if err == nil {
			if attempt > 1 {
				log.Printf("✓ 第%d次重试成功", attempt)
			}
			// 成功获取后保存到缓存
			if err := saveCoinPoolCache(coins); err != nil {
				log.Printf("⚠️  保存币种池缓存失败: %v", err)
			}
			return coins, nil
		}

		lastErr = err
		log.Printf("❌ 第%d次请求失败: %v", attempt, err)
	}

	// API获取失败，尝试使用缓存
	log.Printf("⚠️  API请求全部失败，尝试使用历史缓存数据...")
	cachedCoins, err := loadCoinPoolCache()
	if err == nil {
		log.Printf("✓ 使用历史缓存数据（共%d个币种）", len(cachedCoins))
		return cachedCoins, nil
	}

	// 缓存也失败，使用默认主流币种
	log.Printf("⚠️  无法加载缓存数据（最后错误: %v），使用默认主流币种列表", lastErr)
	return convertSymbolsToCoins(defaultMainstreamCoins), nil
}

// fetchCoinPool 实际执行币种池请求
func fetchCoinPool() ([]CoinInfo, error) {
	log.Printf("🔄 正在请求AI500币种池...")

	client := &http.Client{
		Timeout: coinPoolConfig.Timeout,
	}

	resp, err := client.Get(coinPoolConfig.APIURL)
	if err != nil {
		return nil, fmt.Errorf("请求币种池API失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API返回错误 (status %d): %s", resp.StatusCode, string(body))
	}

	// 解析API响应
	var response CoinPoolAPIResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("JSON解析失败: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("API返回失败状态")
	}

	if len(response.Data.Coins) == 0 {
		return nil, fmt.Errorf("币种列表为空")
	}

	// 设置IsAvailable标志
	coins := response.Data.Coins
	for i := range coins {
		coins[i].IsAvailable = true
	}

	log.Printf("✓ 成功获取%d个币种", len(coins))
	return coins, nil
}

// saveCoinPoolCache 保存币种池到缓存文件
func saveCoinPoolCache(coins []CoinInfo) error {
	// 确保缓存目录存在
	if err := os.MkdirAll(coinPoolConfig.CacheDir, 0755); err != nil {
		return fmt.Errorf("创建缓存目录失败: %w", err)
	}

	cache := CoinPoolCache{
		Coins:      coins,
		FetchedAt:  time.Now(),
		SourceType: "api",
	}

	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化缓存数据失败: %w", err)
	}

	cachePath := filepath.Join(coinPoolConfig.CacheDir, "latest.json")
	if err := ioutil.WriteFile(cachePath, data, 0644); err != nil {
		return fmt.Errorf("写入缓存文件失败: %w", err)
	}

	log.Printf("💾 已保存币种池缓存（%d个币种）", len(coins))
	return nil
}

// loadCoinPoolCache 从缓存文件加载币种池
func loadCoinPoolCache() ([]CoinInfo, error) {
	cachePath := filepath.Join(coinPoolConfig.CacheDir, "latest.json")

	// 检查文件是否存在
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("缓存文件不存在")
	}

	data, err := ioutil.ReadFile(cachePath)
	if err != nil {
		return nil, fmt.Errorf("读取缓存文件失败: %w", err)
	}

	var cache CoinPoolCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, fmt.Errorf("解析缓存数据失败: %w", err)
	}

	// 检查缓存年龄
	cacheAge := time.Since(cache.FetchedAt)
	if cacheAge > 24*time.Hour {
		log.Printf("⚠️  缓存数据较旧（%.1f小时前），但仍可使用", cacheAge.Hours())
	} else {
		log.Printf("📂 缓存数据时间: %s（%.1f分钟前）",
			cache.FetchedAt.Format("2006-01-02 15:04:05"),
			cacheAge.Minutes())
	}

	return cache.Coins, nil
}

// GetAvailableCoins 获取可用的币种列表（过滤不可用的）
func GetAvailableCoins() ([]string, error) {
	coins, err := GetCoinPool()
	if err != nil {
		return nil, err
	}

	var symbols []string
	for _, coin := range coins {
		if coin.IsAvailable {
			// 确保symbol格式正确（转为大写USDT交易对）
			symbol := normalizeSymbol(coin.Pair)
			symbols = append(symbols, symbol)
		}
	}

	if len(symbols) == 0 {
		return nil, fmt.Errorf("没有可用的币种")
	}

	return symbols, nil
}

// GetTopRatedCoins 获取评分最高的N个币种（按评分从大到小排序）
func GetTopRatedCoins(limit int) ([]string, error) {
	coins, err := GetCoinPool()
	if err != nil {
		return nil, err
	}

	// 过滤可用的币种
	var availableCoins []CoinInfo
	for _, coin := range coins {
		if coin.IsAvailable {
			availableCoins = append(availableCoins, coin)
		}
	}

	if len(availableCoins) == 0 {
		return nil, fmt.Errorf("没有可用的币种")
	}

	// 按Score降序排序（冒泡排序）
	for i := 0; i < len(availableCoins); i++ {
		for j := i + 1; j < len(availableCoins); j++ {
			if availableCoins[i].Score < availableCoins[j].Score {
				availableCoins[i], availableCoins[j] = availableCoins[j], availableCoins[i]
			}
		}
	}

	// 取前N个
	maxCount := limit
	if len(availableCoins) < maxCount {
		maxCount = len(availableCoins)
	}

	var symbols []string
	for i := 0; i < maxCount; i++ {
		symbol := normalizeSymbol(availableCoins[i].Pair)
		symbols = append(symbols, symbol)
	}

	return symbols, nil
}

// normalizeSymbol 标准化币种符号
func normalizeSymbol(symbol string) string {
	// 移除空格
	symbol = trimSpaces(symbol)

	// 转为大写
	symbol = toUpper(symbol)

	// 确保以USDT结尾
	if !endsWith(symbol, "USDT") {
		symbol = symbol + "USDT"
	}

	return symbol
}

// 辅助函数
func trimSpaces(s string) string {
	result := ""
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			result += string(s[i])
		}
	}
	return result
}

func toUpper(s string) string {
	result := ""
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c = c - 'a' + 'A'
		}
		result += string(c)
	}
	return result
}

func endsWith(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	return s[len(s)-len(suffix):] == suffix
}

// convertSymbolsToCoins 将币种符号列表转换为CoinInfo列表
func convertSymbolsToCoins(symbols []string) []CoinInfo {
	coins := make([]CoinInfo, 0, len(symbols))
	for _, symbol := range symbols {
		coins = append(coins, CoinInfo{
			Pair:        symbol,
			Score:       0,
			IsAvailable: true,
		})
	}
	return coins
}

// ========== OI Top（持仓量增长Top20）数据 ==========

// OIPosition 持仓量数据
type OIPosition struct {
	Symbol            string  `json:"symbol"`
	Rank              int     `json:"rank"`
	CurrentOI         float64 `json:"current_oi"`          // 当前持仓量
	OIDelta           float64 `json:"oi_delta"`            // 持仓量变化
	OIDeltaPercent    float64 `json:"oi_delta_percent"`    // 持仓量变化百分比
	OIDeltaValue      float64 `json:"oi_delta_value"`      // 持仓量变化价值
	PriceDeltaPercent float64 `json:"price_delta_percent"` // 价格变化百分比
	NetLong           float64 `json:"net_long"`            // 净多仓
	NetShort          float64 `json:"net_short"`           // 净空仓
}

// OITopAPIResponse OI Top API返回的数据结构
type OITopAPIResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Positions []OIPosition `json:"positions"`
		Count     int          `json:"count"`
		Exchange  string       `json:"exchange"`
		TimeRange string       `json:"time_range"`
	} `json:"data"`
}

// OITopCache OI Top 缓存
type OITopCache struct {
	Positions  []OIPosition `json:"positions"`
	FetchedAt  time.Time    `json:"fetched_at"`
	SourceType string       `json:"source_type"`
}

const defaultBinanceOpenInterestURL = "https://fapi.binance.com/fapi/v1/openInterest"

var oiTopConfig = struct {
	APIURL   string
	Timeout  time.Duration
	CacheDir string
	Provider string
}{
	APIURL:   defaultBinanceOpenInterestURL,
	Timeout:  30 * time.Second,
	CacheDir: "coin_pool_cache",
	Provider: "binance",
}

// GetOITopPositions 获取持仓量增长Top20数据（带重试和缓存）
func GetOITopPositions() ([]OIPosition, error) {
	if oiTopConfig.Provider == "disabled" {
		log.Printf("⚠️  已禁用OI Top数据源，跳过持仓量数据获取")
		return []OIPosition{}, nil
	}

	providerLabel := "币安官方API"
	if oiTopConfig.Provider == "custom" {
		providerLabel = "自定义OI Top API"
	}

	log.Printf("🔍 正在使用%s获取持仓量数据...", providerLabel)

	maxRetries := 3
	var lastErr error

	// 尝试从API获取
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			log.Printf("⚠️  第%d次重试获取OI Top数据（共%d次）...", attempt, maxRetries)
			time.Sleep(2 * time.Second)
		}

		positions, err := fetchOITop()
		if err == nil {
			if attempt > 1 {
				log.Printf("✓ 第%d次重试成功", attempt)
			}
			// 成功获取后保存到缓存
			if err := saveOITopCache(positions); err != nil {
				log.Printf("⚠️  保存OI Top缓存失败: %v", err)
			}
			return positions, nil
		}

		lastErr = err
		log.Printf("❌ 第%d次请求OI Top失败: %v", attempt, err)
	}

	// API获取失败，尝试使用缓存
	log.Printf("⚠️  OI Top API请求全部失败，尝试使用历史缓存数据...")
	cachedPositions, err := loadOITopCache()
	if err == nil {
		log.Printf("✓ 使用历史OI Top缓存数据（共%d个币种）", len(cachedPositions))
		return cachedPositions, nil
	}

	// 缓存也失败，返回空列表（OI Top是可选的）
	log.Printf("⚠️  无法加载OI Top缓存数据（最后错误: %v），跳过OI Top数据", lastErr)
	return []OIPosition{}, nil
}

// fetchOITop 实际执行OI Top请求
func fetchOITop() ([]OIPosition, error) {
	if oiTopConfig.Provider == "custom" {
		return fetchOITopFromCustomAPI()
	}
	return fetchOITopFromBinance()
}

// fetchOITopFromCustomAPI 调用自定义OI Top接口
func fetchOITopFromCustomAPI() ([]OIPosition, error) {
	log.Printf("🔄 正在请求OI Top数据...")

	client := &http.Client{
		Timeout: oiTopConfig.Timeout,
	}

	resp, err := client.Get(oiTopConfig.APIURL)
	if err != nil {
		return nil, fmt.Errorf("请求OI Top API失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取OI Top响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OI Top API返回错误 (status %d): %s", resp.StatusCode, string(body))
	}

	// 解析API响应
	var response OITopAPIResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("OI Top JSON解析失败: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("OI Top API返回失败状态")
	}

	if len(response.Data.Positions) == 0 {
		return nil, fmt.Errorf("OI Top持仓列表为空")
	}

	log.Printf("✓ 成功获取%d个OI Top币种（时间范围: %s）",
		len(response.Data.Positions), response.Data.TimeRange)
	return response.Data.Positions, nil
}

// fetchOITopFromBinance 使用币安开放API获取持仓量数据
func fetchOITopFromBinance() ([]OIPosition, error) {
	log.Printf("🔄 正在从币安官方API获取持仓量数据...")

	coins, err := GetCoinPool()
	if err != nil {
		log.Printf("⚠️  获取币种池失败，使用默认币种列表: %v", err)
		coins = convertSymbolsToCoins(defaultMainstreamCoins)
	}

	symbolSet := make(map[string]struct{})
	for _, coin := range coins {
		symbol := normalizeSymbol(coin.Pair)
		symbolSet[symbol] = struct{}{}
	}
	// 确保默认币种始终被包含
	for _, symbol := range defaultMainstreamCoins {
		symbolSet[normalizeSymbol(symbol)] = struct{}{}
	}

	const maxSymbols = 40
	symbols := make([]string, 0, len(symbolSet))
	for symbol := range symbolSet {
		symbols = append(symbols, symbol)
	}
	sort.Strings(symbols)
	if len(symbols) > maxSymbols {
		symbols = symbols[:maxSymbols]
	}

	if len(symbols) == 0 {
		return nil, fmt.Errorf("没有可用于获取持仓量的币种")
	}

	prevPositions, _ := loadOITopCache()
	prevMap := make(map[string]OIPosition, len(prevPositions))
	for _, pos := range prevPositions {
		prevMap[strings.ToUpper(pos.Symbol)] = pos
	}

	client := &http.Client{
		Timeout: oiTopConfig.Timeout,
	}

	var positions []OIPosition
	for _, symbol := range symbols {
		currentOI, err := fetchBinanceOpenInterest(client, oiTopConfig.APIURL, symbol)
		if err != nil {
			log.Printf("⚠️  获取%s持仓量失败: %v", symbol, err)
			continue
		}

		position := OIPosition{
			Symbol:    symbol,
			CurrentOI: currentOI,
		}

		if prev, ok := prevMap[symbol]; ok {
			position.OIDelta = currentOI - prev.CurrentOI
			if prev.CurrentOI != 0 {
				position.OIDeltaPercent = (position.OIDelta / prev.CurrentOI) * 100
			}
			position.OIDeltaValue = position.OIDelta
			position.PriceDeltaPercent = prev.PriceDeltaPercent
			position.NetLong = prev.NetLong
			position.NetShort = prev.NetShort
		} else {
			position.OIDelta = 0
			position.OIDeltaPercent = 0
			position.OIDeltaValue = 0
		}

		positions = append(positions, position)
	}

	if len(positions) == 0 {
		return nil, fmt.Errorf("未能从币安获取任何持仓量数据")
	}

	sort.Slice(positions, func(i, j int) bool {
		if positions[i].OIDeltaPercent == positions[j].OIDeltaPercent {
			return positions[i].CurrentOI > positions[j].CurrentOI
		}
		return positions[i].OIDeltaPercent > positions[j].OIDeltaPercent
	})

	if len(positions) > 20 {
		positions = positions[:20]
	}

	for i := range positions {
		positions[i].Rank = i + 1
	}

	return positions, nil
}

func fetchBinanceOpenInterest(client *http.Client, baseURL, symbol string) (float64, error) {
	url := baseURL
	if strings.Contains(baseURL, "?") {
		url = fmt.Sprintf("%s&symbol=%s", baseURL, symbol)
	} else {
		url = fmt.Sprintf("%s?symbol=%s", baseURL, symbol)
	}

	resp, err := client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("请求币安持仓量失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("读取币安持仓量响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("币安持仓量API返回错误 (status %d): %s", resp.StatusCode, string(body))
	}

	var payload struct {
		Symbol       string `json:"symbol"`
		OpenInterest string `json:"openInterest"`
		Time         int64  `json:"time"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, fmt.Errorf("解析币安持仓量JSON失败: %w", err)
	}

	openInterest, err := strconv.ParseFloat(payload.OpenInterest, 64)
	if err != nil {
		return 0, fmt.Errorf("解析币安持仓量数值失败: %w", err)
	}

	return openInterest, nil
}

// saveOITopCache 保存OI Top数据到缓存
func saveOITopCache(positions []OIPosition) error {
	if err := os.MkdirAll(oiTopConfig.CacheDir, 0755); err != nil {
		return fmt.Errorf("创建缓存目录失败: %w", err)
	}

	cache := OITopCache{
		Positions:  positions,
		FetchedAt:  time.Now(),
		SourceType: oiTopConfig.Provider,
	}
	if cache.SourceType == "" {
		cache.SourceType = "unknown"
	}

	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化OI Top缓存数据失败: %w", err)
	}

	cachePath := filepath.Join(oiTopConfig.CacheDir, "oi_top_latest.json")
	if err := ioutil.WriteFile(cachePath, data, 0644); err != nil {
		return fmt.Errorf("写入OI Top缓存文件失败: %w", err)
	}

	log.Printf("💾 已保存OI Top缓存（%d个币种）", len(positions))
	return nil
}

// loadOITopCache 从缓存加载OI Top数据
func loadOITopCache() ([]OIPosition, error) {
	cachePath := filepath.Join(oiTopConfig.CacheDir, "oi_top_latest.json")

	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("OI Top缓存文件不存在")
	}

	data, err := ioutil.ReadFile(cachePath)
	if err != nil {
		return nil, fmt.Errorf("读取OI Top缓存文件失败: %w", err)
	}

	var cache OITopCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, fmt.Errorf("解析OI Top缓存数据失败: %w", err)
	}

	cacheAge := time.Since(cache.FetchedAt)
	if cacheAge > 24*time.Hour {
		log.Printf("⚠️  OI Top缓存数据较旧（%.1f小时前），但仍可使用", cacheAge.Hours())
	} else {
		log.Printf("📂 OI Top缓存数据时间: %s（%.1f分钟前）",
			cache.FetchedAt.Format("2006-01-02 15:04:05"),
			cacheAge.Minutes())
	}

	return cache.Positions, nil
}

// GetOITopSymbols 获取OI Top的币种符号列表
func GetOITopSymbols() ([]string, error) {
	positions, err := GetOITopPositions()
	if err != nil {
		return nil, err
	}

	var symbols []string
	for _, pos := range positions {
		symbol := normalizeSymbol(pos.Symbol)
		symbols = append(symbols, symbol)
	}

	return symbols, nil
}

// MergedCoinPool 合并的币种池（AI500 + OI Top）
type MergedCoinPool struct {
	AI500Coins    []CoinInfo          // AI500评分币种
	OITopCoins    []OIPosition        // 持仓量增长Top20
	AllSymbols    []string            // 所有不重复的币种符号
	SymbolSources map[string][]string // 每个币种的来源（"ai500"/"oi_top"）
}

// GetMergedCoinPool 获取合并后的币种池（AI500 + OI Top，去重）
func GetMergedCoinPool(ai500Limit int) (*MergedCoinPool, error) {
	// 1. 获取AI500数据
	ai500TopSymbols, err := GetTopRatedCoins(ai500Limit)
	if err != nil {
		log.Printf("⚠️  获取AI500数据失败: %v", err)
		ai500TopSymbols = []string{} // 失败时用空列表
	}

	// 2. 获取OI Top数据
	oiTopSymbols, err := GetOITopSymbols()
	if err != nil {
		log.Printf("⚠️  获取OI Top数据失败: %v", err)
		oiTopSymbols = []string{} // 失败时用空列表
	}

	// 3. 合并并去重
	symbolSet := make(map[string]bool)
	symbolSources := make(map[string][]string)

	// 添加AI500币种
	for _, symbol := range ai500TopSymbols {
		symbolSet[symbol] = true
		symbolSources[symbol] = append(symbolSources[symbol], "ai500")
	}

	// 添加OI Top币种
	for _, symbol := range oiTopSymbols {
		if !symbolSet[symbol] {
			symbolSet[symbol] = true
		}
		symbolSources[symbol] = append(symbolSources[symbol], "oi_top")
	}

	// 转换为数组
	var allSymbols []string
	for symbol := range symbolSet {
		allSymbols = append(allSymbols, symbol)
	}

	// 获取完整数据
	ai500Coins, _ := GetCoinPool()
	oiTopPositions, _ := GetOITopPositions()

	merged := &MergedCoinPool{
		AI500Coins:    ai500Coins,
		OITopCoins:    oiTopPositions,
		AllSymbols:    allSymbols,
		SymbolSources: symbolSources,
	}

	log.Printf("📊 币种池合并完成: AI500=%d, OI_Top=%d, 总计(去重)=%d",
		len(ai500TopSymbols), len(oiTopSymbols), len(allSymbols))

	return merged, nil
}
