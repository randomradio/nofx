package trader

import "time"

// OrderFillInfo captures execution details returned by an exchange for a single order.
type OrderFillInfo struct {
	Quantity        float64
	AvgPrice        float64
	Commission      float64
	CommissionAsset string
}

// OrderFillFetcher is implemented by trader backends that can expose post-trade execution data.
type OrderFillFetcher interface {
	GetOrderFillInfo(symbol string, orderID int64) (*OrderFillInfo, error)
}

// CommissionEntry represents a single commission record returned by the exchange.
type CommissionEntry struct {
	TranID int64
	Asset  string
	Amount float64
	Time   time.Time
}

// CommissionHistoryProvider exposes access to recent commission history.
type CommissionHistoryProvider interface {
	GetRecentCommissions(symbol string, since time.Time) ([]CommissionEntry, error)
}

// TradeFill captures an executed trade fill returned by an exchange.
type TradeFill struct {
	OrderID         int64
	Price           float64
	Quantity        float64
	Commission      float64
	CommissionAsset string
	Time            time.Time
	Side            string
	PositionSide    string
	RealizedPnL     float64
}

// TradeHistoryProvider exposes access to recent trade fills.
type TradeHistoryProvider interface {
	GetRecentFills(symbol string, since time.Time) ([]TradeFill, error)
}
