package decision

import (
	"encoding/json"
	"fmt"
	"log"
	"nofx/market"
	"nofx/mcp"
	"nofx/pool"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PositionInfo describes an open perpetual position
type PositionInfo struct {
	Symbol           string  `json:"symbol"`
	Side             string  `json:"side"` // "long" or "short"
	EntryPrice       float64 `json:"entry_price"`
	MarkPrice        float64 `json:"mark_price"`
	Quantity         float64 `json:"quantity"`
	Leverage         int     `json:"leverage"`
	UnrealizedPnL    float64 `json:"unrealized_pnl"`
	UnrealizedPnLPct float64 `json:"unrealized_pnl_pct"`
	LiquidationPrice float64 `json:"liquidation_price"`
	MarginUsed       float64 `json:"margin_used"`
	UpdateTime       int64   `json:"update_time"` // last update timestamp (ms)
}

// AccountInfo captures current account state
type AccountInfo struct {
	TotalEquity      float64 `json:"total_equity"`      // net account equity
	AvailableBalance float64 `json:"available_balance"` // free balance
	TotalPnL         float64 `json:"total_pnl"`         // cumulative PnL
	TotalPnLPct      float64 `json:"total_pnl_pct"`     // cumulative PnL percent
	MarginUsed       float64 `json:"margin_used"`       // margin currently locked
	MarginUsedPct    float64 `json:"margin_used_pct"`   // margin usage percent
	PositionCount    int     `json:"position_count"`    // number of open positions
}

// CandidateCoin represents a symbol from the coin pool
type CandidateCoin struct {
	Symbol  string   `json:"symbol"`
	Sources []string `json:"sources"` // sources: "ai500" and/or "oi_top"
}

// OITopData captures top open-interest changes for decision-making
type OITopData struct {
	Rank              int     // OI top rank
	OIDeltaPercent    float64 // 1h open-interest percent change
	OIDeltaValue      float64 // open-interest notional change
	PriceDeltaPercent float64 // price percent change
	NetLong           float64 // net long positioning
	NetShort          float64 // net short positioning
}

// Context aggregates all information passed to the AI
type Context struct {
	CurrentTime     string                  `json:"current_time"`
	RuntimeMinutes  int                     `json:"runtime_minutes"`
	CallCount       int                     `json:"call_count"`
	Account         AccountInfo             `json:"account"`
	Positions       []PositionInfo          `json:"positions"`
	CandidateCoins  []CandidateCoin         `json:"candidate_coins"`
	MarketDataMap   map[string]*market.Data `json:"-"` // in-memory market data cache
	OITopDataMap    map[string]*OITopData   `json:"-"` // open-interest lookup
	Performance     interface{}             `json:"-"` // historical performance analysis payload
	BTCETHLeverage  int                     `json:"-"` // leverage cap for BTC/ETH (from config)
	AltcoinLeverage int                     `json:"-"` // leverage cap for altcoins (from config)
}

// Decision represents one trading action from the AI
type Decision struct {
	Symbol          string  `json:"symbol"`
	Action          string  `json:"action"` // "open_long", "open_short", "close_long", "close_short", "hold", "wait"
	Leverage        int     `json:"leverage,omitempty"`
	PositionSizeUSD float64 `json:"position_size_usd,omitempty"`
	StopLoss        float64 `json:"stop_loss,omitempty"`
	TakeProfit      float64 `json:"take_profit,omitempty"`
	Confidence      int     `json:"confidence,omitempty"` // confidence (0-100)
	RiskUSD         float64 `json:"risk_usd,omitempty"`   // maximum USD risk
	Reasoning       string  `json:"reasoning"`
}

// FullDecision packages the AI response including chain-of-thought
type FullDecision struct {
	UserPrompt string     `json:"user_prompt"` // prompt sent to the AI
	CoTTrace   string     `json:"cot_trace"`   // chain-of-thought text from AI
	Decisions  []Decision `json:"decisions"`   // list of actionable decisions
	Timestamp  time.Time  `json:"timestamp"`
}

// GetFullDecision retrieves the full AI decision for all tracked symbols
func GetFullDecision(ctx *Context, mcpClient *mcp.Client) (*FullDecision, error) {
	// 1. Fetch market data for every required symbol
	if err := fetchMarketDataForContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to fetch market data: %w", err)
	}

	// 2. Build system (static rules) and user (dynamic data) prompts
	systemPrompt := buildSystemPrompt(ctx.Account.TotalEquity, ctx.BTCETHLeverage, ctx.AltcoinLeverage)
	userPrompt := buildUserPrompt(ctx)

	// 3. Submit both prompts to the AI API
	aiResponse, err := mcpClient.CallWithMessages(systemPrompt, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("failed to call AI API: %w", err)
	}

	fmt.Printf("ai response: %s", aiResponse)

	// 4. Parse AI response
	decision, err := parseFullDecisionResponse(aiResponse, ctx.Account.TotalEquity, ctx.BTCETHLeverage, ctx.AltcoinLeverage)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AI response: %w", err)
	}

	decision.Timestamp = time.Now()
	decision.UserPrompt = userPrompt // store the prompt that was sent
	return decision, nil
}

// fetchMarketDataForContext populates market and OI data for every symbol in scope
func fetchMarketDataForContext(ctx *Context) error {
	ctx.MarketDataMap = make(map[string]*market.Data)
	ctx.OITopDataMap = make(map[string]*OITopData)

	// Collect every symbol that requires data
	symbolSet := make(map[string]bool)

	// 1. Always include symbols we currently hold
	for _, pos := range ctx.Positions {
		symbolSet[pos.Symbol] = true
	}

	// 2. Add candidate symbols up to the configured allowance
	maxCandidates := calculateMaxCandidates(ctx)
	for i, coin := range ctx.CandidateCoins {
		if i >= maxCandidates {
			break
		}
		symbolSet[coin.Symbol] = true
	}

	// Fetch market data; track which symbols already exist in positions
	positionSymbols := make(map[string]bool)
	for _, pos := range ctx.Positions {
		positionSymbols[pos.Symbol] = true
	}

	for symbol := range symbolSet {
		data, err := market.Get(symbol)
		if err != nil {
			// Skip single-symbol failures; partial data is acceptable
			continue
		}

		// ⚠️ Liquidity filter: ignore new symbols with notional OI below 15M USD, but keep existing holdings
		isExistingPosition := positionSymbols[symbol]
		if !isExistingPosition && data.OpenInterest != nil && data.CurrentPrice > 0 {
			oiValue := data.OpenInterest.Latest * data.CurrentPrice
			oiValueInMillions := oiValue / 1_000_000 // convert to millions USD
			if oiValueInMillions < 15 {
				log.Printf("⚠️  %s skipped due to low OI notional (%.2fM USD < 15M) [OI: %.0f × Price: %.4f]",
					symbol, oiValueInMillions, data.OpenInterest.Latest, data.CurrentPrice)
				continue
			}
		}

		ctx.MarketDataMap[symbol] = data
	}

	// Load OI Top data (best-effort)
	oiPositions, err := pool.GetOITopPositions()
	if err == nil {
		for _, pos := range oiPositions {
			symbol := pos.Symbol
			ctx.OITopDataMap[symbol] = &OITopData{
				Rank:              pos.Rank,
				OIDeltaPercent:    pos.OIDeltaPercent,
				OIDeltaValue:      pos.OIDeltaValue,
				PriceDeltaPercent: pos.PriceDeltaPercent,
				NetLong:           pos.NetLong,
				NetShort:          pos.NetShort,
			}
		}
	}

	return nil
}

// calculateMaxCandidates determines how many candidates to analyze
func calculateMaxCandidates(ctx *Context) int {
	// The candidate list is already filtered upstream; analyze everything provided.
	return len(ctx.CandidateCoins)
}

// buildSystemPrompt constructs the system prompt (static rules that can be cached)
func buildSystemPrompt(accountEquity float64, btcEthLeverage, altcoinLeverage int) string {
	var sb strings.Builder

	// === Mission ===
	sb.WriteString("You are a professional cryptocurrency trading AI executing autonomous strategies on Binance perpetual futures.\n\n")
	sb.WriteString("# 🎯 Core Objective\n\n")
	sb.WriteString("**Maximize the Sharpe Ratio**\n\n")
	sb.WriteString("Sharpe Ratio = average return / return volatility\n\n")
	sb.WriteString("**This means you must:**\n")
	sb.WriteString("- ✅ Focus on high-quality setups (edge, strong R:R) to lift Sharpe\n")
	sb.WriteString("- ✅ Maintain steady returns and control drawdowns\n")
	sb.WriteString("- ✅ Be patient with winners and let profits run\n")
	sb.WriteString("- ❌ Avoid frequent low-quality trades that add noise\n")
	sb.WriteString("- ❌ Prevent overtrading and fee drag\n")
	sb.WriteString("- ❌ Do not scalp in and out prematurely\n\n")
	sb.WriteString("**Key insight:** the system polls every 3 minutes, but you are not obligated to trade each cycle.\n")
	sb.WriteString("Most cycles should end with `wait` or `hold`; only enter when the opportunity is exceptional.\n\n")

	// === Hard constraints (risk control) ===
	sb.WriteString("# ⚖️ Hard Constraints (Risk Control)\n\n")
	sb.WriteString("1. **Risk/Reward:** must be ≥ 1:3 (risk 1%, target 3%+)\n")
	sb.WriteString("2. **Open positions:** maximum of 3 symbols (quality over quantity)\n")
	sb.WriteString(fmt.Sprintf("3. **Per-symbol sizing:** Alts %.0f-%.0f USDT (%dx leverage) | BTC/ETH %.0f-%.0f USDT (%dx leverage)\n",
		accountEquity*0.8, accountEquity*1.5, altcoinLeverage, accountEquity*5, accountEquity*10, btcEthLeverage))
	sb.WriteString("4. **Margin usage:** total usage ≤ 90%\n\n")

	// === Long/short symmetry ===
	sb.WriteString("# 📉 Balance Longs vs Shorts\n\n")
	sb.WriteString("**Important:** profits from shorting downtrends equal profits from longing uptrends.\n\n")
	sb.WriteString("- Uptrending market → go long\n")
	sb.WriteString("- Downtrending market → go short\n")
	sb.WriteString("- Choppy/sideways → wait\n\n")
	sb.WriteString("**Never bias toward longs; shorting is a core tool.**\n\n")

	// === Trading cadence ===
	sb.WriteString("# ⏱️ Trading Cadence Expectations\n\n")
	sb.WriteString("**Benchmarks:**\n")
	sb.WriteString("- Elite traders: 2–4 trades per day ≈ 0.1–0.2 per hour\n")
	sb.WriteString("- Overtrading: >2 trades per hour → critical issue\n")
	sb.WriteString("- Preferred rhythm: hold each position at least 30–60 minutes\n\n")
	sb.WriteString("**Self-check:**\n")
	sb.WriteString("If you trade every cycle → standards are too low.\n")
	sb.WriteString("If you exit within <30 minutes → you are too impatient.\n\n")

	// === Entry requirements ===
	sb.WriteString("# 🎯 Entry Criteria (Strict)\n\n")
	sb.WriteString("Only open positions on **strong signals**. When unsure, stay flat.\n\n")
	sb.WriteString("**Available data:**\n")
	sb.WriteString("- 📊 **Raw series:** 3-minute mid-price history + 4-hour candles\n")
	sb.WriteString("- 📈 **Technical series:** EMA20, MACD, RSI7, RSI14 sequences\n")
	sb.WriteString("- 💰 **Flow series:** volume, open interest, funding rate\n")
	sb.WriteString("- 🎯 **Tags:** AI500 rating / OI Top ranking when present\n\n")
	sb.WriteString("**Analysis (choose what works best):**\n")
	sb.WriteString("- Any combination of trend analysis, pattern recognition, support/resistance, fib levels, volatility bands, etc.\n")
	sb.WriteString("- Cross-validate across price, volume, OI, indicators, and structure\n")
	sb.WriteString("- Open only when aggregate confidence ≥ 75\n\n")
	sb.WriteString("**Do not trade on weak signals:**\n")
	sb.WriteString("- Single-dimension triggers\n")
	sb.WriteString("- Conflicting evidence (e.g., price up while volume fades)\n")
	sb.WriteString("- Range-bound chop\n")
	sb.WriteString("- Same symbol reopened within 15 minutes of closing\n\n")

	// === Sharpe-driven adaptation ===
	sb.WriteString("# 🧬 Sharpe Ratio Feedback Loop\n\n")
	sb.WriteString("You receive the **Sharpe Ratio** each cycle as performance feedback:\n\n")
	sb.WriteString("**Sharpe < -0.5** (persistent loss):\n")
	sb.WriteString("  → 🛑 Stop trading; observe for at least 6 cycles (18 minutes)\n")
	sb.WriteString("  → 🔍 Diagnose root causes:\n")
	sb.WriteString("     • Trading too often? (>2 opens per hour)\n")
	sb.WriteString("     • Holding too briefly? (<30 minutes per trade)\n")
	sb.WriteString("     • Signal quality too low? (confidence < 75)\n")
	sb.WriteString("     • Ignoring shorts? (long-only bias)\n\n")
	sb.WriteString("**Sharpe -0.5 to 0** (minor drawdown):\n")
	sb.WriteString("  → ⚠️ Restrict to confidence > 80\n")
	sb.WriteString("  → Cap new entries to ≤1 per hour\n")
	sb.WriteString("  → Extend holding time to ≥30 minutes\n\n")
	sb.WriteString("**Sharpe 0 to 0.7** (solid performance):\n")
	sb.WriteString("  → ✅ Continue current playbook\n\n")
	sb.WriteString("**Sharpe > 0.7** (excellent):\n")
	sb.WriteString("  → 🚀 You may scale size modestly\n\n")
	sb.WriteString("**Key point:** Sharpe is the north star—it naturally punishes overtrading and churn.\n\n")

	// === Decision workflow ===
	sb.WriteString("# 📋 Decision Workflow\n\n")
	sb.WriteString("1. **Evaluate Sharpe:** Is the strategy working? Any adjustments?\n")
	sb.WriteString("2. **Review positions:** Has trend/risk changed? Time to trim/exit?\n")
	sb.WriteString("3. **Scan for setups:** Do you see a strong long or short opportunity?\n")
	sb.WriteString("4. **Produce output:** Chain-of-thought + JSON instructions\n\n")

	// === Output format ===
	sb.WriteString("# 📤 Output Format\n\n")
	sb.WriteString("**Step 1: JSON decision array (mandatory)**\n")
	sb.WriteString("- Emit exactly one `json` code block\n")
	sb.WriteString("- Even with no actions you must return an empty array `[]`\n\n")
	sb.WriteString("```json\n[\n")
	sb.WriteString(fmt.Sprintf("  {\"symbol\": \"BTCUSDT\", \"action\": \"open_short\", \"leverage\": %d, \"position_size_usd\": %.0f, \"stop_loss\": 97000, \"take_profit\": 91000, \"confidence\": 85, \"risk_usd\": 300, \"reasoning\": \"Downtrend confirmation + MACD bear cross\"},\n", btcEthLeverage, accountEquity*5))
	sb.WriteString("  {\"symbol\": \"ETHUSDT\", \"action\": \"close_long\", \"reasoning\": \"Target hit, locking in profit\"}\n")
	sb.WriteString("]\n```\n\n")
	sb.WriteString("**Step 2: Chain-of-thought (≤200 words)**\n")
	sb.WriteString("Briefly explain your reasoning, key signals, and risk control.\n\n")
	sb.WriteString("**Field guide:**\n")
	sb.WriteString("- `action`: open_long | open_short | close_long | close_short | hold | wait\n")
	sb.WriteString("- `confidence`: 0-100 (new trades should be ≥ 75)\n")
	sb.WriteString("- When opening, you must provide leverage, position_size_usd, stop_loss, take_profit, confidence, risk_usd, reasoning\n\n")

	// === Key reminders ===
	sb.WriteString("---\n\n")
	sb.WriteString("**Remember:**\n")
	sb.WriteString("- Optimize for Sharpe, not trade count\n")
	sb.WriteString("- Shorts are as valuable as longs\n")
	sb.WriteString("- Passing on a trade is fine; avoid low-quality setups\n")
	sb.WriteString("- Minimum risk/reward is 1:3\n")

	return sb.String()
}

// buildUserPrompt assembles the dynamic user-facing prompt
func buildUserPrompt(ctx *Context) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("It has been %d minutes since you started trading. The current time is %s and you've been invoked %d times. Below, we are providing you with a variety of state data, price data, and predictive signals so you can discover alpha. Below that is your current account information, value, performance, positions, etc.\n\n",
		ctx.RuntimeMinutes, ctx.CurrentTime, ctx.CallCount))

	sb.WriteString("ALL OF THE PRICE OR SIGNAL DATA BELOW IS ORDERED: OLDEST -> NEWEST\n\n")
	sb.WriteString("Timeframes note: Unless stated otherwise in a section title, intraday series are provided at 3-minute intervals. If a coin uses a different interval, it is explicitly stated in that coin's section.\n\n")
	sb.WriteString("----\n\n")
	sb.WriteString("CURRENT MARKET STATE FOR ALL COINS\n\n")

	// Prioritize core trading pairs first, then show remaining symbols
	primarySymbols := []string{"BTCUSDT", "ETHUSDT", "SOLUSDT", "BNBUSDT", "XRPUSDT", "DOGEUSDT"}
	shown := make(map[string]bool)

	for _, symbol := range primarySymbols {
		data, ok := ctx.MarketDataMap[symbol]
		if !ok {
			continue
		}
		sb.WriteString(formatCoinSectionForPrompt(data))
		shown[symbol] = true
	}

	var remaining []string
	for symbol := range ctx.MarketDataMap {
		if shown[symbol] {
			continue
		}
		remaining = append(remaining, symbol)
	}
	sort.Strings(remaining)
	for _, symbol := range remaining {
		sb.WriteString(formatCoinSectionForPrompt(ctx.MarketDataMap[symbol]))
	}

	sb.WriteString("HERE IS YOUR ACCOUNT INFORMATION & PERFORMANCE\n\n")
	sb.WriteString(fmt.Sprintf("Current Total Return (percent): %s%%\n", formatFloat(ctx.Account.TotalPnLPct)))
	sb.WriteString(fmt.Sprintf("Available Cash: %s\n", formatFloat(ctx.Account.AvailableBalance)))
	sb.WriteString(fmt.Sprintf("Current Account Value: %s\n\n", formatFloat(ctx.Account.TotalEquity)))

	sb.WriteString("Current live positions & performance:\n")
	if len(ctx.Positions) == 0 {
		sb.WriteString("None\n")
	} else {
		for _, pos := range ctx.Positions {
			sb.WriteString(formatPositionForPrompt(pos))
			sb.WriteString("\n")
		}
	}

	if ctx.Performance != nil {
		type PerformanceData struct {
			SharpeRatio float64 `json:"sharpe_ratio"`
		}
		var perfData PerformanceData
		if jsonData, err := json.Marshal(ctx.Performance); err == nil {
			if err := json.Unmarshal(jsonData, &perfData); err == nil {
				sb.WriteString(fmt.Sprintf("Sharpe Ratio: %s\n", formatFloat(perfData.SharpeRatio)))
			}
		}
	}

	return strings.TrimSpace(sb.String())
}

func formatCoinSectionForPrompt(data *market.Data) string {
	var sb strings.Builder

	displaySymbol := trimSymbolSuffix(data.Symbol)
	sb.WriteString(fmt.Sprintf("ALL %s DATA\n\n", displaySymbol))
	sb.WriteString(fmt.Sprintf("current_price = %s, current_ema20 = %s, current_macd = %s, current_rsi (7 period) = %s\n\n",
		formatFloat(data.CurrentPrice),
		formatFloat(data.CurrentEMA20),
		formatFloat(data.CurrentMACD),
		formatFloat(data.CurrentRSI7)))

	sb.WriteString(fmt.Sprintf("In addition, here is the latest %s open interest and funding rate for perps:\n\n", displaySymbol))
	if data.OpenInterest != nil {
		sb.WriteString(fmt.Sprintf("Open Interest: Latest: %s  Average: %s\n\n",
			formatFloat(data.OpenInterest.Latest),
			formatFloat(data.OpenInterest.Average)))
	} else {
		sb.WriteString("Open Interest: Latest: 0  Average: 0\n\n")
	}
	sb.WriteString(fmt.Sprintf("Funding Rate: %s\n\n", formatFloat(data.FundingRate)))

	if data.IntradaySeries != nil {
		sb.WriteString("Intraday series (3-minute intervals, oldest -> latest):\n\n")
		if len(data.IntradaySeries.MidPrices) > 0 {
			sb.WriteString(fmt.Sprintf("Mid prices: %s\n\n", formatFloatSliceForPrompt(data.IntradaySeries.MidPrices)))
		}
		if len(data.IntradaySeries.EMA20Values) > 0 {
			sb.WriteString(fmt.Sprintf("EMA indicators (20-period): %s\n\n", formatFloatSliceForPrompt(data.IntradaySeries.EMA20Values)))
		}
		if len(data.IntradaySeries.MACDValues) > 0 {
			sb.WriteString(fmt.Sprintf("MACD indicators: %s\n\n", formatFloatSliceForPrompt(data.IntradaySeries.MACDValues)))
		}
		if len(data.IntradaySeries.RSI7Values) > 0 {
			sb.WriteString(fmt.Sprintf("RSI indicators (7-Period): %s\n\n", formatFloatSliceForPrompt(data.IntradaySeries.RSI7Values)))
		}
		if len(data.IntradaySeries.RSI14Values) > 0 {
			sb.WriteString(fmt.Sprintf("RSI indicators (14-Period): %s\n\n", formatFloatSliceForPrompt(data.IntradaySeries.RSI14Values)))
		}
	}

	if data.LongerTermContext != nil {
		sb.WriteString("Longer-term context (4-hour timeframe):\n\n")
		sb.WriteString(fmt.Sprintf("20-Period EMA: %s vs. 50-Period EMA: %s\n\n",
			formatFloat(data.LongerTermContext.EMA20),
			formatFloat(data.LongerTermContext.EMA50)))
		sb.WriteString(fmt.Sprintf("3-Period ATR: %s vs. 14-Period ATR: %s\n\n",
			formatFloat(data.LongerTermContext.ATR3),
			formatFloat(data.LongerTermContext.ATR14)))
		sb.WriteString(fmt.Sprintf("Current Volume: %s vs. Average Volume: %s\n\n",
			formatFloat(data.LongerTermContext.CurrentVolume),
			formatFloat(data.LongerTermContext.AverageVolume)))

		if len(data.LongerTermContext.MACDValues) > 0 {
			sb.WriteString(fmt.Sprintf("MACD indicators: %s\n\n", formatFloatSliceForPrompt(data.LongerTermContext.MACDValues)))
		}
		if len(data.LongerTermContext.RSI14Values) > 0 {
			sb.WriteString(fmt.Sprintf("RSI indicators (14-Period): %s\n\n", formatFloatSliceForPrompt(data.LongerTermContext.RSI14Values)))
		}
	}

	return strings.TrimSpace(sb.String()) + "\n"
}

func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'g', -1, 64)
}

func formatFloatSliceForPrompt(values []float64) string {
	if len(values) == 0 {
		return "[]"
	}
	formatted := make([]string, len(values))
	for i, v := range values {
		formatted[i] = formatFloat(v)
	}
	return "[" + strings.Join(formatted, ", ") + "]"
}

func trimSymbolSuffix(symbol string) string {
	symbol = strings.ToUpper(symbol)
	if strings.HasSuffix(symbol, "USDT") {
		return strings.TrimSuffix(symbol, "USDT")
	}
	return symbol
}

func formatPositionForPrompt(pos PositionInfo) string {
	displaySymbol := trimSymbolSuffix(pos.Symbol)

	quantity := pos.Quantity
	if pos.Side == "short" && quantity > 0 {
		quantity = -quantity
	}

	notional := pos.Quantity * pos.MarkPrice
	if notional < 0 {
		notional = -notional
	}

	fields := []string{
		fmt.Sprintf("'symbol': '%s'", displaySymbol),
		fmt.Sprintf("'side': '%s'", strings.ToLower(pos.Side)),
		fmt.Sprintf("'quantity': %s", formatFloat(quantity)),
		fmt.Sprintf("'entry_price': %s", formatFloat(pos.EntryPrice)),
		fmt.Sprintf("'current_price': %s", formatFloat(pos.MarkPrice)),
		fmt.Sprintf("'liquidation_price': %s", formatFloat(pos.LiquidationPrice)),
		fmt.Sprintf("'unrealized_pnl': %s", formatFloat(pos.UnrealizedPnL)),
		fmt.Sprintf("'unrealized_pnl_pct': %s", formatFloat(pos.UnrealizedPnLPct)),
		fmt.Sprintf("'leverage': %d", pos.Leverage),
		fmt.Sprintf("'margin_used': %s", formatFloat(pos.MarginUsed)),
		fmt.Sprintf("'notional_usd': %s", formatFloat(notional)),
		fmt.Sprintf("'update_time_ms': %d", pos.UpdateTime),
	}

	return "{" + strings.Join(fields, ", ") + "}"
}

// parseFullDecisionResponse extracts the chain-of-thought and decisions from the AI response
func parseFullDecisionResponse(aiResponse string, accountEquity float64, btcEthLeverage, altcoinLeverage int) (*FullDecision, error) {
	// 1. Capture chain-of-thought text
	cotTrace := extractCoTTrace(aiResponse)
	fmt.Printf("ai response: %s, \n CoT: %s", aiResponse, cotTrace)

	// 2. Extract JSON decision array
	decisions, err := extractDecisions(aiResponse)
	if err != nil {
		return &FullDecision{
			CoTTrace:  cotTrace,
			Decisions: []Decision{},
		}, fmt.Errorf("failed to extract decisions: %w\n\n=== AI chain-of-thought ===\n%s", err, cotTrace)
	}

	// 3. Validate decisions
	if err := validateDecisions(decisions, accountEquity, btcEthLeverage, altcoinLeverage); err != nil {
		return &FullDecision{
			CoTTrace:  cotTrace,
			Decisions: decisions,
		}, fmt.Errorf("decision validation failed: %w\n\n=== AI chain-of-thought ===\n%s", err, cotTrace)
	}

	return &FullDecision{
		CoTTrace:  cotTrace,
		Decisions: decisions,
	}, nil
}

// extractCoTTrace pulls out the chain-of-thought narrative
func extractCoTTrace(response string) string {
	// Prefer text around the ```json block
	blockStart, blockEnd, _ := findFirstCodeFence(response)
	if blockStart >= 0 && blockEnd > blockStart {
		// First try the text after the JSON, otherwise fall back to text before it
		after := strings.TrimSpace(response[blockEnd:])
		if after != "" {
			return after
		}
		before := strings.TrimSpace(response[:blockStart])
		if before != "" {
			return before
		}
	}

	// Fallback: split the response at the first '['
	jsonStart := strings.Index(response, "[")
	if jsonStart > 0 {
		return strings.TrimSpace(response[:jsonStart])
	}

	return strings.TrimSpace(response)
}

// extractDecisions pulls the JSON decision array from the response
func extractDecisions(response string) ([]Decision, error) {
	// 1) Prefer content inside a ```json block
	if start, end, lang := findFirstCodeFence(response); start >= 0 && end > start {
		content := response[start:end]
		// Only try to parse if it looks like an array
		if strings.Contains(content, "[") {
			if decisions, err := parseDecisionsFromJSONFragment(content); err == nil {
				return decisions, nil
			} else {
				// If the block fails to parse, fall back to global search
				_ = lang
			}
		}
	}

	// 2) Fallback: find the first well-formed JSON array in the entire response
	arrayStart := strings.Index(response, "[")
	if arrayStart == -1 {
		return nil, fmt.Errorf("unable to find JSON array start")
	}
	arrayEnd := findMatchingBracket(response, arrayStart)
	if arrayEnd == -1 {
		return nil, fmt.Errorf("unable to find JSON array end")
	}
	fragment := strings.TrimSpace(response[arrayStart : arrayEnd+1])
	return parseDecisionsFromJSONFragment(fragment)
}

// parseDecisionsFromJSONFragment parses a snippet containing a JSON array
func parseDecisionsFromJSONFragment(fragment string) ([]Decision, error) {
	// Re-locate the first array within the fragment
	start := strings.Index(fragment, "[")
	if start == -1 {
		return nil, fmt.Errorf("unable to find JSON array start")
	}
	end := findMatchingBracket(fragment, start)
	if end == -1 {
		return nil, fmt.Errorf("unable to find JSON array end")
	}
	jsonContent := strings.TrimSpace(fragment[start : end+1])
	jsonContent = fixMissingQuotes(jsonContent)
	var decisions []Decision
	if err := json.Unmarshal([]byte(jsonContent), &decisions); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w\nJSON: %s", err, jsonContent)
	}
	return decisions, nil
}

// fixMissingQuotes swaps smart quotes with ASCII equivalents
func fixMissingQuotes(jsonStr string) string {
	jsonStr = strings.ReplaceAll(jsonStr, "\u201c", "\"") // "
	jsonStr = strings.ReplaceAll(jsonStr, "\u201d", "\"") // "
	jsonStr = strings.ReplaceAll(jsonStr, "\u2018", "'")  // '
	jsonStr = strings.ReplaceAll(jsonStr, "\u2019", "'")  // '
	return jsonStr
}

// validateDecisions checks every decision using account context and leverage limits
func validateDecisions(decisions []Decision, accountEquity float64, btcEthLeverage, altcoinLeverage int) error {
	for i, decision := range decisions {
		if err := validateDecision(&decision, accountEquity, btcEthLeverage, altcoinLeverage); err != nil {
			return fmt.Errorf("decision #%d failed validation: %w", i+1, err)
		}
	}
	return nil
}

// findMatchingBracket returns the index of the matching closing bracket
func findMatchingBracket(s string, start int) int {
	if start >= len(s) || s[start] != '[' {
		return -1
	}

	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i
			}
		}
	}

	return -1
}

// findFirstCodeFence finds the first triple-backtick code block and returns its bounds plus language tag
func findFirstCodeFence(s string) (int, int, string) {
	fence := "```"
	i := strings.Index(s, fence)
	if i == -1 {
		return -1, -1, ""
	}

	// Read the language hint (until newline)
	rest := s[i+len(fence):]
	nl := strings.IndexByte(rest, '\n')
	if nl == -1 {
		return -1, -1, ""
	}
	lang := strings.TrimSpace(strings.ToLower(rest[:nl]))
	contentStart := i + len(fence) + nl + 1

	// Find the closing fence
	j := strings.Index(s[contentStart:], fence)
	if j == -1 {
		return -1, -1, lang
	}
	contentEnd := contentStart + j
	return contentStart, contentEnd, lang
}

// validateDecision confirms a single decision obeys guardrails
func validateDecision(d *Decision, accountEquity float64, btcEthLeverage, altcoinLeverage int) error {
	// Validate action
	validActions := map[string]bool{
		"open_long":   true,
		"open_short":  true,
		"close_long":  true,
		"close_short": true,
		"hold":        true,
		"wait":        true,
	}

	if !validActions[d.Action] {
		return fmt.Errorf("invalid action: %s", d.Action)
	}

	// Opening trades require full parameter set
	if d.Action == "open_long" || d.Action == "open_short" {
		// Use configured leverage caps by symbol type
		maxLeverage := altcoinLeverage          // altcoin leverage ceiling
		maxPositionValue := accountEquity * 1.5 // altcoins: ≤1.5× account equity
		if d.Symbol == "BTCUSDT" || d.Symbol == "ETHUSDT" {
			maxLeverage = btcEthLeverage          // BTC/ETH leverage ceiling
			maxPositionValue = accountEquity * 10 // BTC/ETH: ≤10× account equity
		}

		if d.Leverage <= 0 || d.Leverage > maxLeverage {
			return fmt.Errorf("leverage must be between 1 and %d (%s configured max %dx): %d", maxLeverage, d.Symbol, maxLeverage, d.Leverage)
		}
		if d.PositionSizeUSD <= 0 {
			return fmt.Errorf("position size must be > 0: %.2f", d.PositionSizeUSD)
		}
		// Allow 1% tolerance to avoid floating-point drift
		tolerance := maxPositionValue * 0.01
		if d.PositionSizeUSD > maxPositionValue+tolerance {
			if d.Symbol == "BTCUSDT" || d.Symbol == "ETHUSDT" {
				return fmt.Errorf("BTC/ETH position value cannot exceed %.0f USDT (10× account equity). Got %.0f", maxPositionValue, d.PositionSizeUSD)
			} else {
				return fmt.Errorf("Altcoin position value cannot exceed %.0f USDT (1.5× account equity). Got %.0f", maxPositionValue, d.PositionSizeUSD)
			}
		}
		if d.StopLoss <= 0 || d.TakeProfit <= 0 {
			return fmt.Errorf("stop loss and take profit must be > 0")
		}

		// Confirm stop-loss/take-profit ordering
		if d.Action == "open_long" {
			if d.StopLoss >= d.TakeProfit {
				return fmt.Errorf("for longs the stop loss must be below the take profit")
			}
		} else {
			if d.StopLoss <= d.TakeProfit {
				return fmt.Errorf("for shorts the stop loss must be above the take profit")
			}
		}

		// Enforce minimum 1:3 risk/reward
		var entryPrice float64
		if d.Action == "open_long" {
			entryPrice = d.StopLoss + (d.TakeProfit-d.StopLoss)*0.2 // assume entry 20% above stop
		} else {
			entryPrice = d.StopLoss - (d.StopLoss-d.TakeProfit)*0.2 // assume entry 20% below stop
		}

		var riskPercent, rewardPercent, riskRewardRatio float64
		if d.Action == "open_long" {
			riskPercent = (entryPrice - d.StopLoss) / entryPrice * 100
			rewardPercent = (d.TakeProfit - entryPrice) / entryPrice * 100
			if riskPercent > 0 {
				riskRewardRatio = rewardPercent / riskPercent
			}
		} else {
			riskPercent = (d.StopLoss - entryPrice) / entryPrice * 100
			rewardPercent = (entryPrice - d.TakeProfit) / entryPrice * 100
			if riskPercent > 0 {
				riskRewardRatio = rewardPercent / riskPercent
			}
		}

		if riskRewardRatio < 3.0 {
			return fmt.Errorf("risk/reward is too low (%.2f:1); minimum is 3.0:1 [risk: %.2f%% reward: %.2f%%] [stop: %.2f take-profit: %.2f]",
				riskRewardRatio, riskPercent, rewardPercent, d.StopLoss, d.TakeProfit)
		}
	}

	return nil
}
