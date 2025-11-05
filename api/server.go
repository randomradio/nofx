package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"nofx/config"
	"nofx/manager"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// Server HTTP API服务器
type Server struct {
	router        *gin.Engine
	traderManager *manager.TraderManager
	port          int
	systemConfig  *config.Config
	userSignals   userSignalSourceConfig
	userSignalsMu sync.RWMutex

	authEnabled  bool
	authUsername string
	passwordHash []byte
	tokenSecret  []byte
	tokenTTL     time.Duration
}

type promptTemplateDefinition struct {
	Description  string
	SystemPrompt string
}

type userSignalSourceConfig struct {
	UseCoinPool bool      `json:"use_coin_pool"`
	UseOITop    bool      `json:"use_oi_top"`
	UpdatedAt   time.Time `json:"updated_at"`
}

var builtInPromptTemplateOrder = []string{"default", "aggressive"}

var builtInPromptTemplates = map[string]promptTemplateDefinition{
	"default": {
		Description: "Balanced template emphasizing structured analysis and capital preservation.",
		SystemPrompt: `You are NOFX, a disciplined crypto derivatives trader managing multiple strategies.
Always produce decisions in clear sections:
1. Market context (trend, momentum, liquidity)
2. Risk posture and volatility regime
3. Exact trade plan (symbol, side, size, leverage, entry, stops, targets)
4. Account impact and risk checks
Respect configured leverage caps, margin mode, and drawdown limits.
Never exceed available balance, never leave JSON fields empty, and always justify actions with on-chain or order book signals.`,
	},
	"aggressive": {
		Description: "Higher-risk template favoring rapid momentum plays with tight controls.",
		SystemPrompt: `You are NOFX-AGGRO, a high-frequency crypto momentum trader.
Prioritize fast-moving narratives, breakout structures, and funding imbalances.
Workflow:
- Scan for coins with unusual volume, OI spikes, or news catalysts.
- Enter positions decisively with predefined invalidation levels.
- Use partial take-profits and trail stops aggressively to protect gains.
Stay within account limits, honour stop rules, and avoid averaging down losing trades.`,
	},
}

// NewServer 创建API服务器
func NewServer(traderManager *manager.TraderManager, cfg *config.Config) (*Server, error) {
	// 设置为Release模式（减少日志输出）
	gin.SetMode(gin.ReleaseMode)

	router := gin.Default()

	// 启用CORS
	router.Use(corsMiddleware())

	var (
		port    = 8080
		authCfg config.AuthConfig
		signals userSignalSourceConfig
	)

	if cfg != nil {
		if cfg.APIServerPort > 0 {
			port = cfg.APIServerPort
		}
		authCfg = cfg.Auth
		signals.UseCoinPool = cfg.UseDefaultCoins
		signals.UseOITop = cfg.OITopAPIURL != ""
		signals.UpdatedAt = time.Now()
	}

	s := &Server{
		router:        router,
		traderManager: traderManager,
		port:          port,
		systemConfig:  cfg,
		userSignals:   signals,
	}

	if authCfg.Enabled {
		hash, err := bcrypt.GenerateFromPassword([]byte(authCfg.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("生成密码哈希失败: %w", err)
		}
		s.authEnabled = true
		s.authUsername = authCfg.Username
		s.passwordHash = hash
		s.tokenSecret = []byte(authCfg.TokenSecret)
		if authCfg.TokenTTLMinutes <= 0 {
			authCfg.TokenTTLMinutes = 720
		}
		s.tokenTTL = time.Duration(authCfg.TokenTTLMinutes) * time.Minute
	}

	// 设置路由
	s.setupRoutes()

	return s, nil
}

// corsMiddleware CORS中间件
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	}
}

// setupRoutes 设置路由
func (s *Server) setupRoutes() {
	// 健康检查
	s.router.Any("/health", s.handleHealth)

	s.router.POST("/auth/login", s.handleLogin)

	// 公共API路由组（无需认证）
	publicAPI := s.router.Group("/api")
	{
		publicAPI.Any("/health", s.handleHealth)
		publicAPI.POST("/register", s.handleRegister)
		publicAPI.POST("/login", s.handleLogin)
		publicAPI.POST("/verify-otp", s.handleVerifyOTP)
		publicAPI.POST("/complete-registration", s.handleCompleteRegistration)
		publicAPI.GET("/supported-models", s.handleGetSupportedModels)
		publicAPI.GET("/supported-exchanges", s.handleGetSupportedExchanges)
		publicAPI.GET("/config", s.handleGetSystemConfig)
		publicAPI.GET("/prompt-templates", s.handleGetPromptTemplates)
		publicAPI.GET("/prompt-templates/:name", s.handleGetPromptTemplate)
		publicAPI.GET("/traders", s.handlePublicTraderList)
		publicAPI.GET("/competition", s.handlePublicCompetition)
		publicAPI.GET("/equity-history", s.handleEquityHistory)
	}

	// 受保护的API路由组（需要认证）
	protected := s.router.Group("/api")
	if s.authEnabled {
		protected.Use(s.authMiddleware())
	}
	{
		protected.GET("/models", s.handleGetModelConfigs)
		protected.PUT("/models", s.handleUpdateModelConfigs)
		protected.GET("/exchanges", s.handleGetExchangeConfigs)
		protected.PUT("/exchanges", s.handleUpdateExchangeConfigs)
		protected.GET("/user/signal-sources", s.handleGetUserSignalSource)
		protected.POST("/user/signal-sources", s.handleSaveUserSignalSource)
		protected.GET("/status", s.handleStatus)
		protected.GET("/account", s.handleAccount)
		protected.GET("/positions", s.handlePositions)
		protected.GET("/decisions", s.handleDecisions)
		protected.GET("/decisions/latest", s.handleLatestDecisions)
		protected.GET("/statistics", s.handleStatistics)
		protected.GET("/performance", s.handlePerformance)
	}
}

// handleRegister 注册接口（暂未启用）
func (s *Server) handleRegister(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "registration flow is not enabled",
	})
}

// handleVerifyOTP OTP验证接口（暂未启用）
func (s *Server) handleVerifyOTP(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "otp verification is not enabled",
	})
}

// handleCompleteRegistration 完成注册接口（暂未启用）
func (s *Server) handleCompleteRegistration(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "registration completion is not enabled",
	})
}

// handleGetSupportedModels 返回支持的AI模型列表
func (s *Server) handleGetSupportedModels(c *gin.Context) {
	type modelInfo struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Provider    string `json:"provider"`
		Description string `json:"description"`
	}

	models := []modelInfo{
		{
			ID:          "deepseek",
			Name:        "DeepSeek (deepseek-chat)",
			Provider:    "DeepSeek",
			Description: "Balanced reasoning-first model optimised for structured trading analysis.",
		},
		{
			ID:          "qwen",
			Name:        "Qwen (qwen-plus)",
			Provider:    "Alibaba Cloud",
			Description: "Multilingual model suited for bilingual trading workflows and Chinese market data.",
		},
		{
			ID:          "custom",
			Name:        "Custom OpenAI-Compatible Model",
			Provider:    "User Supplied",
			Description: "Use your own API endpoint, API key, and model name as defined in config.json.",
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"models": models,
	})
}

// handleGetSupportedExchanges 返回支持的交易所列表
func (s *Server) handleGetSupportedExchanges(c *gin.Context) {
	type exchangeInfo struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Type        string `json:"type"`
		Description string `json:"description"`
	}

	exchanges := []exchangeInfo{
		{
			ID:          "binance",
			Name:        "Binance Futures",
			Type:        "cex",
			Description: "Centralised exchange USDT-margined perpetual contracts with deep liquidity.",
		},
		{
			ID:          "hyperliquid",
			Name:        "Hyperliquid Perps",
			Type:        "dex",
			Description: "On-chain perpetual DEX with fast settlement and transparent funding.",
		},
		{
			ID:          "aster",
			Name:        "Aster Perps",
			Type:        "dex",
			Description: "Aster network perpetual exchange (testnet recommended for evaluation).",
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"exchanges": exchanges,
	})
}

// handleGetModelConfigs 返回模型配置摘要（不包含敏感信息）
func (s *Server) handleGetModelConfigs(c *gin.Context) {
	type modelConfig struct {
		ID             string `json:"id"`
		Name           string `json:"name"`
		Provider       string `json:"provider"`
		Description    string `json:"description"`
		RequiresAPIKey bool   `json:"requires_api_key"`
		Enabled        bool   `json:"enabled"`
	}

	models := []modelConfig{
		{
			ID:             "deepseek",
			Name:           "DeepSeek (deepseek-chat)",
			Provider:       "DeepSeek",
			Description:    "Requires a DeepSeek API key. Suitable for deep reasoning on complex trade setups.",
			RequiresAPIKey: true,
		},
		{
			ID:             "qwen",
			Name:           "Qwen (qwen-plus)",
			Provider:       "Alibaba Cloud",
			Description:    "Requires DashScope access token. Strong bilingual support for Chinese market narratives.",
			RequiresAPIKey: true,
		},
		{
			ID:             "custom",
			Name:           "Custom OpenAI-Compatible",
			Provider:       "User Supplied",
			Description:    "Provide your own API URL, key, and model name (OpenAI-compatible schema).",
			RequiresAPIKey: true,
		},
	}

	if s.systemConfig != nil {
		for _, traderCfg := range s.systemConfig.Traders {
			if !traderCfg.Enabled {
				continue
			}
			for idx := range models {
				if models[idx].ID == traderCfg.AIModel {
					models[idx].Enabled = true
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"models": models,
	})
}

// handleUpdateModelConfigs 更新模型配置（当前仅返回未实现）
func (s *Server) handleUpdateModelConfigs(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "model configuration updates are not available via API yet",
	})
}

// handleGetExchangeConfigs 返回交易所配置摘要（不包含密钥）
func (s *Server) handleGetExchangeConfigs(c *gin.Context) {
	type exchangeConfig struct {
		ID             string `json:"id"`
		Name           string `json:"name"`
		Type           string `json:"type"`
		Description    string `json:"description"`
		RequiresAPIKey bool   `json:"requires_api_key"`
		Enabled        bool   `json:"enabled"`
	}

	exchanges := []exchangeConfig{
		{
			ID:             "binance",
			Name:           "Binance Futures",
			Type:           "cex",
			Description:    "Requires API key and secret. Supports rich derivatives instruments.",
			RequiresAPIKey: true,
		},
		{
			ID:             "hyperliquid",
			Name:           "Hyperliquid Perps",
			Type:           "dex",
			Description:    "Requires private key and wallet address. On-chain settlement DEX.",
			RequiresAPIKey: true,
		},
		{
			ID:             "aster",
			Name:           "Aster Perps",
			Type:           "dex",
			Description:    "Requires signer credentials. Optimised for testnet experimentation.",
			RequiresAPIKey: true,
		},
	}

	if s.systemConfig != nil {
		for _, traderCfg := range s.systemConfig.Traders {
			if !traderCfg.Enabled {
				continue
			}
			for idx := range exchanges {
				if exchanges[idx].ID == traderCfg.Exchange {
					exchanges[idx].Enabled = true
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"exchanges": exchanges,
	})
}

// handleUpdateExchangeConfigs 更新交易所配置（当前仅返回未实现）
func (s *Server) handleUpdateExchangeConfigs(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "exchange configuration updates are not available via API yet",
	})
}

// handleGetUserSignalSource 获取用户信号源偏好
func (s *Server) handleGetUserSignalSource(c *gin.Context) {
	s.userSignalsMu.RLock()
	current := s.userSignals
	s.userSignalsMu.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"config": current,
	})
}

// handleSaveUserSignalSource 保存用户信号源偏好（进程内存储）
func (s *Server) handleSaveUserSignalSource(c *gin.Context) {
	var req struct {
		UseCoinPool bool `json:"use_coin_pool"`
		UseOITop    bool `json:"use_oi_top"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	s.userSignalsMu.Lock()
	s.userSignals.UseCoinPool = req.UseCoinPool
	s.userSignals.UseOITop = req.UseOITop
	s.userSignals.UpdatedAt = time.Now()
	updated := s.userSignals
	s.userSignalsMu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"config": updated,
	})
}

// handleGetSystemConfig 返回安全的系统配置（不包含敏感信息）
func (s *Server) handleGetSystemConfig(c *gin.Context) {
	defaultCoins := []string{
		"BTCUSDT",
		"ETHUSDT",
		"SOLUSDT",
		"BNBUSDT",
		"XRPUSDT",
		"DOGEUSDT",
		"ADAUSDT",
		"HYPEUSDT",
	}
	useDefaultCoins := true
	coinPoolAPI := ""
	oiTopAPI := ""

	if s.systemConfig != nil {
		if len(s.systemConfig.DefaultCoins) > 0 {
			defaultCoins = append([]string(nil), s.systemConfig.DefaultCoins...)
		}
		useDefaultCoins = s.systemConfig.UseDefaultCoins
		coinPoolAPI = s.systemConfig.CoinPoolAPIURL
		oiTopAPI = s.systemConfig.OITopAPIURL
	}

	c.JSON(http.StatusOK, gin.H{
		"use_default_coins": useDefaultCoins,
		"default_coins":     defaultCoins,
		"coin_pool_api_url": coinPoolAPI,
		"oi_top_api_url":    oiTopAPI,
	})
}

// handleGetPromptTemplates 返回内置提示词模板列表
func (s *Server) handleGetPromptTemplates(c *gin.Context) {
	type templateInfo struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	templates := make([]templateInfo, 0, len(builtInPromptTemplateOrder))
	for _, name := range builtInPromptTemplateOrder {
		if tpl, ok := builtInPromptTemplates[name]; ok {
			templates = append(templates, templateInfo{
				Name:        name,
				Description: tpl.Description,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"templates": templates,
	})
}

// handleGetPromptTemplate 返回指定提示词模板的详细内容
func (s *Server) handleGetPromptTemplate(c *gin.Context) {
	name := strings.ToLower(strings.TrimSpace(c.Param("name")))
	if name == "" {
		name = "default"
	}

	tpl, ok := builtInPromptTemplates[name]
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{
			"error": fmt.Sprintf("prompt template '%s' not found", name),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"name":          name,
		"description":   tpl.Description,
		"system_prompt": tpl.SystemPrompt,
	})
}

// handlePublicTraderList 公共Trader列表
func (s *Server) handlePublicTraderList(c *gin.Context) {
	s.handleTraderList(c)
}

// handlePublicCompetition 公共竞赛数据
func (s *Server) handlePublicCompetition(c *gin.Context) {
	s.handleCompetition(c)
}

// authMiddleware 鉴权中间件
func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		tokenString := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if err := s.validateToken(tokenString); err != nil {
			log.Printf("⚠️  Token验证失败: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.Next()
	}
}

// handleLogin 登录接口
func (s *Server) handleLogin(c *gin.Context) {
	if !s.authEnabled {
		c.JSON(http.StatusNotFound, gin.H{"error": "authentication disabled"})
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if subtle.ConstantTimeCompare([]byte(req.Username), []byte(s.authUsername)) != 1 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword(s.passwordHash, []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	tokenString, expiresAt, err := s.issueToken()
	if err != nil {
		log.Printf("❌ 生成token失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      tokenString,
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
		"expires_in": int(s.tokenTTL.Seconds()),
	})
}

// handleHealth 健康检查
func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"time":   c.Request.Context().Value("time"),
	})
}

// getTraderFromQuery 从query参数获取trader
func (s *Server) getTraderFromQuery(c *gin.Context) (*manager.TraderManager, string, error) {
	traderID := c.Query("trader_id")
	if traderID == "" {
		// 如果没有指定trader_id，返回第一个trader
		ids := s.traderManager.GetTraderIDs()
		if len(ids) == 0 {
			return nil, "", fmt.Errorf("没有可用的trader")
		}
		traderID = ids[0]
	}
	return s.traderManager, traderID, nil
}

// handleCompetition 竞赛总览（对比所有trader）
func (s *Server) handleCompetition(c *gin.Context) {
	comparison, err := s.traderManager.GetComparisonData()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("获取对比数据失败: %v", err),
		})
		return
	}
	c.JSON(http.StatusOK, comparison)
}

// handleTraderList trader列表
func (s *Server) handleTraderList(c *gin.Context) {
	traders := s.traderManager.GetAllTraders()
	result := make([]map[string]interface{}, 0, len(traders))

	for _, t := range traders {
		result = append(result, map[string]interface{}{
			"trader_id":   t.GetID(),
			"trader_name": t.GetName(),
			"ai_model":    t.GetAIModel(),
		})
	}

	c.JSON(http.StatusOK, result)
}

// handleStatus 系统状态
func (s *Server) handleStatus(c *gin.Context) {
	_, traderID, err := s.getTraderFromQuery(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	trader, err := s.traderManager.GetTrader(traderID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	status := trader.GetStatus()
	c.JSON(http.StatusOK, status)
}

// handleAccount 账户信息
func (s *Server) handleAccount(c *gin.Context) {
	_, traderID, err := s.getTraderFromQuery(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	trader, err := s.traderManager.GetTrader(traderID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	log.Printf("📊 收到账户信息请求 [%s]", trader.GetName())
	account, err := trader.GetAccountInfo()
	if err != nil {
		log.Printf("❌ 获取账户信息失败 [%s]: %v", trader.GetName(), err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("获取账户信息失败: %v", err),
		})
		return
	}

	log.Printf("✓ 返回账户信息 [%s]: 净值=%.2f, 可用=%.2f, 盈亏=%.2f (%.2f%%)",
		trader.GetName(),
		account["total_equity"],
		account["available_balance"],
		account["total_pnl"],
		account["total_pnl_pct"])
	c.JSON(http.StatusOK, account)
}

// handlePositions 持仓列表
func (s *Server) handlePositions(c *gin.Context) {
	_, traderID, err := s.getTraderFromQuery(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	trader, err := s.traderManager.GetTrader(traderID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	positions, err := trader.GetPositions()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("获取持仓列表失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, positions)
}

// handleDecisions 决策日志列表
func (s *Server) handleDecisions(c *gin.Context) {
	_, traderID, err := s.getTraderFromQuery(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	trader, err := s.traderManager.GetTrader(traderID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// 获取所有历史决策记录（无限制）
	records, err := trader.GetDecisionLogger().GetLatestRecords(10000)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("获取决策日志失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, records)
}

// handleLatestDecisions 最新决策日志（最近5条，最新的在前）
func (s *Server) handleLatestDecisions(c *gin.Context) {
	_, traderID, err := s.getTraderFromQuery(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	trader, err := s.traderManager.GetTrader(traderID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	records, err := trader.GetDecisionLogger().GetLatestRecords(5)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("获取决策日志失败: %v", err),
		})
		return
	}

	// 反转数组，让最新的在前面（用于列表显示）
	// GetLatestRecords返回的是从旧到新（用于图表），这里需要从新到旧
	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}

	c.JSON(http.StatusOK, records)
}

// handleStatistics 统计信息
func (s *Server) handleStatistics(c *gin.Context) {
	_, traderID, err := s.getTraderFromQuery(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	trader, err := s.traderManager.GetTrader(traderID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	stats, err := trader.GetDecisionLogger().GetStatistics()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("获取统计信息失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// handleEquityHistory 收益率历史数据
func (s *Server) handleEquityHistory(c *gin.Context) {
	_, traderID, err := s.getTraderFromQuery(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	trader, err := s.traderManager.GetTrader(traderID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// 获取尽可能多的历史数据（几天的数据）
	// 每3分钟一个周期：10000条 = 约20天的数据
	records, err := trader.GetDecisionLogger().GetLatestRecords(10000)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("获取历史数据失败: %v", err),
		})
		return
	}

	// 构建收益率历史数据点
	type EquityPoint struct {
		Timestamp        string  `json:"timestamp"`
		TotalEquity      float64 `json:"total_equity"`      // 账户净值（wallet + unrealized）
		AvailableBalance float64 `json:"available_balance"` // 可用余额
		TotalPnL         float64 `json:"total_pnl"`         // 总盈亏（相对初始余额）
		TotalPnLPct      float64 `json:"total_pnl_pct"`     // 总盈亏百分比
		PositionCount    int     `json:"position_count"`    // 持仓数量
		MarginUsedPct    float64 `json:"margin_used_pct"`   // 保证金使用率
		CycleNumber      int     `json:"cycle_number"`
	}

	// 从AutoTrader获取初始余额（用于计算盈亏百分比）
	initialBalance := 0.0
	if status := trader.GetStatus(); status != nil {
		if ib, ok := status["initial_balance"].(float64); ok && ib > 0 {
			initialBalance = ib
		}
	}

	// 如果无法从status获取，且有历史记录，则从第一条记录获取
	if initialBalance == 0 && len(records) > 0 {
		// 第一条记录的equity作为初始余额
		initialBalance = records[0].AccountState.TotalBalance
	}

	// 如果还是无法获取，返回错误
	if initialBalance == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "无法获取初始余额",
		})
		return
	}

	var history []EquityPoint
	for _, record := range records {
		// TotalBalance字段实际存储的是TotalEquity
		totalEquity := record.AccountState.TotalBalance
		// TotalUnrealizedProfit字段实际存储的是TotalPnL（相对初始余额）
		totalPnL := record.AccountState.TotalUnrealizedProfit

		// 计算盈亏百分比
		totalPnLPct := 0.0
		if initialBalance > 0 {
			totalPnLPct = (totalPnL / initialBalance) * 100
		}

		history = append(history, EquityPoint{
			Timestamp:        record.Timestamp.Format("2006-01-02 15:04:05"),
			TotalEquity:      totalEquity,
			AvailableBalance: record.AccountState.AvailableBalance,
			TotalPnL:         totalPnL,
			TotalPnLPct:      totalPnLPct,
			PositionCount:    record.AccountState.PositionCount,
			MarginUsedPct:    record.AccountState.MarginUsedPct,
			CycleNumber:      record.CycleNumber,
		})
	}

	c.JSON(http.StatusOK, history)
}

// handlePerformance AI历史表现分析（用于展示AI学习和反思）
func (s *Server) handlePerformance(c *gin.Context) {
	_, traderID, err := s.getTraderFromQuery(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	trader, err := s.traderManager.GetTrader(traderID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// 分析最近100个周期的交易表现（避免长期持仓的交易记录丢失）
	// 假设每3分钟一个周期，100个周期 = 5小时，足够覆盖大部分交易
	performance, err := trader.GetDecisionLogger().AnalyzePerformance(100)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("分析历史表现失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, performance)
}

// Start 启动服务器
func (s *Server) Start() error {
	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("🌐 API服务器启动在 http://localhost%s", addr)
	log.Printf("📊 API文档:")
	log.Printf("  • GET  /api/health           - 健康检查")
	log.Printf("  • GET  /api/traders          - 公开的AI交易员列表（无需认证）")
	log.Printf("  • GET  /api/competition      - 公开的竞赛数据（无需认证）")
	log.Printf("  • GET  /api/equity-history?trader_id=xxx - 公开的收益率历史数据（无需认证，竞赛用）")
	log.Printf("  • POST /api/traders          - 创建新的AI交易员")
	log.Printf("  • DELETE /api/traders/:id    - 删除AI交易员")
	log.Printf("  • POST /api/traders/:id/start - 启动AI交易员")
	log.Printf("  • POST /api/traders/:id/stop  - 停止AI交易员")
	log.Printf("  • GET  /api/models           - 获取AI模型配置")
	log.Printf("  • PUT  /api/models           - 更新AI模型配置")
	log.Printf("  • GET  /api/exchanges        - 获取交易所配置")
	log.Printf("  • PUT  /api/exchanges        - 更新交易所配置")
	log.Printf("  • GET  /api/status?trader_id=xxx     - 指定trader的系统状态")
	log.Printf("  • GET  /api/account?trader_id=xxx    - 指定trader的账户信息")
	log.Printf("  • GET  /api/positions?trader_id=xxx  - 指定trader的持仓列表")
	log.Printf("  • GET  /api/decisions?trader_id=xxx  - 指定trader的决策日志")
	log.Printf("  • GET  /api/decisions/latest?trader_id=xxx - 指定trader的最新决策")
	log.Printf("  • GET  /api/statistics?trader_id=xxx - 指定trader的统计信息")
	log.Printf("  • GET  /api/performance?trader_id=xxx - 指定trader的AI学习表现分析")
	log.Printf("  • GET  /health               - 健康检查")
	log.Println()
	if s.authEnabled {
		log.Printf("🔐 已启用API认证，用户名: %s", s.authUsername)
		log.Println()
	}

	return s.router.Run(addr)
}

type tokenPayload struct {
	Username string `json:"u"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
	Nonce    string `json:"n"`
}

func (s *Server) issueToken() (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(s.tokenTTL)

	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("生成随机数失败: %w", err)
	}

	payload := tokenPayload{
		Username: s.authUsername,
		IssuedAt: now.Unix(),
		Expires:  expiresAt.Unix(),
		Nonce:    base64.RawURLEncoding.EncodeToString(randomBytes),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("序列化token失败: %w", err)
	}

	signature := s.signToken(payloadBytes)
	token := fmt.Sprintf("%s.%s",
		base64.RawURLEncoding.EncodeToString(payloadBytes),
		base64.RawURLEncoding.EncodeToString(signature),
	)

	return token, expiresAt, nil
}

func (s *Server) validateToken(token string) error {
	if token == "" {
		return errors.New("token为空")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return errors.New("token格式错误")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("token解码失败: %w", err)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("签名解码失败: %w", err)
	}

	expectedSig := s.signToken(payloadBytes)
	if len(expectedSig) != len(sigBytes) ||
		subtle.ConstantTimeCompare(expectedSig, sigBytes) != 1 {
		return errors.New("签名无效")
	}

	var payload tokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return fmt.Errorf("解析token失败: %w", err)
	}

	if subtle.ConstantTimeCompare([]byte(payload.Username), []byte(s.authUsername)) != 1 {
		return errors.New("用户名不匹配")
	}

	if time.Now().Unix() > payload.Expires {
		return errors.New("token已过期")
	}

	return nil
}

func (s *Server) signToken(data []byte) []byte {
	mac := hmac.New(sha256.New, s.tokenSecret)
	mac.Write(data)
	return mac.Sum(nil)
}
