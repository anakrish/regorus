(declare-fun defined_input.context.ip () Bool)
(declare-fun defined_input.resource () Bool)
(declare-fun defined_input.action () Bool)
(declare-fun defined_input.principal () Bool)
(declare-fun input.context.ip () String)
(declare-fun input.resource () String)
(declare-fun input.action () String)
(declare-fun input.principal () String)
(assert (and true
     defined_input.context.ip
     defined_input.principal
     defined_input.action
     defined_input.resource
     defined_input.context.ip))
(assert (let ((a!1 (and (or (= input.principal "User::admins")
                    (= input.principal "User::alice"))
                (= input.action "Action::view")
                (= input.resource "File::budget")
                (str.in_re input.context.ip (re.++ (str.to_re "10.") re.all))
                (not false))))
  (= (ite a!1 1 0) 1)))
