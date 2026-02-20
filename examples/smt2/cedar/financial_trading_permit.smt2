(declare-fun defined_input.resource () Bool)
(declare-fun defined_input.action () Bool)
(declare-fun defined_input.principal () Bool)
(declare-fun defined_input.context.market_open () Bool)
(declare-fun defined_input.context.region () Bool)
(declare-fun defined_input.context.trade_value () Bool)
(declare-fun input.context.region () String)
(declare-fun input.resource () String)
(declare-fun input.action () String)
(declare-fun input.principal () String)
(declare-fun input.context.market_open () Bool)
(declare-fun input.context.trade_value () Int)
(assert (and true
     defined_input.context.trade_value
     defined_input.context.region
     defined_input.context.market_open
     defined_input.context.trade_value
     defined_input.context.region
     defined_input.context.market_open
     defined_input.context.region
     (and (and defined_input.principal
               defined_input.action
               defined_input.resource)
          defined_input.context.trade_value
          defined_input.context.region
          defined_input.context.market_open)
     (and (and defined_input.principal
               defined_input.action
               defined_input.resource)
          defined_input.context.trade_value
          defined_input.context.region
          defined_input.context.market_open)
     (and defined_input.principal defined_input.action defined_input.resource)))
(assert (let ((a!1 (and (or (= input.principal "Team::trading-desk")
                    (= input.principal "Team::senior-traders")
                    (= input.principal "User::alice")
                    (= input.principal "User::bob"))
                (= input.action "Action::executeTrade")
                (= input.resource "Market::NYSE")
                (<= input.context.trade_value 1000000)
                (str.in_re input.context.region
                           (re.++ (str.to_re "US-") re.all))
                (= input.context.market_open true)))
      (a!2 (and (or (= input.principal "Team::senior-traders")
                    (= input.principal "User::bob"))
                (= input.action "Action::executeTrade")
                (= input.resource "Market::NYSE")
                (<= input.context.trade_value 50000000)
                (str.in_re input.context.region
                           (re.++ (str.to_re "US-") re.all))
                (= input.context.market_open true)))
      (a!4 (and defined_input.resource
                defined_input.context.region
                true
                true
                (= input.resource "Market::NYSE")
                (str.in_re input.context.region
                           (re.++ (str.to_re "SANC-") re.all)))))
(let ((a!3 (or a!1
               a!2
               (and (or (= input.principal "Role::compliance")
                        (= input.principal "User::carol"))
                    (or (= input.action "Action::auditLog")
                        (= input.action "Action::reviewTrade"))
                    (= input.resource "Market::NYSE")
                    true))))
  (= (ite (and a!3 (not a!4)) 1 0) 1))))
