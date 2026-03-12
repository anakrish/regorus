// Financial trading platform — tiered permissions with geo-fencing.
//
// Traders may execute trades up to their risk tier's limit,
// but only from approved regions and during market hours.
// Compliance officers can review any trade.
// All access is denied from sanctioned countries.

permit(
  principal in Team::"trading-desk",
  action == Action::"executeTrade",
  resource == Market::"NYSE"
)
when {
  context.trade_value >= 1000 &&
  context.trade_value <= 1000000 &&
  context.region like "US-*" &&
  context.market_open == true
};

permit(
  principal in Team::"senior-traders",
  action == Action::"executeTrade",
  resource == Market::"NYSE"
)
when {
  context.trade_value >= 1000 &&
  context.trade_value <= 50000000 &&
  context.region like "US-*" &&
  context.market_open == true
};

permit(
  principal in Role::"compliance",
  action in [Action::"reviewTrade", Action::"auditLog"],
  resource == Market::"NYSE"
);

// Block all access from sanctioned regions.
forbid(
  principal,
  action,
  resource == Market::"NYSE"
)
when {
  context.region like "SANC-*"
};
