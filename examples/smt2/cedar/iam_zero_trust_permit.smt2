(declare-fun defined_input.context.ip () Bool)
(declare-fun defined_input.context.mfa () Bool)
(declare-fun defined_input.resource () Bool)
(declare-fun defined_input.action () Bool)
(declare-fun defined_input.principal () Bool)
(declare-fun defined_input.context.suspended () Bool)
(declare-fun input.context.suspended () Bool)
(declare-fun input.resource () String)
(declare-fun input.action () String)
(declare-fun input.principal () String)
(declare-fun input.context.ip () String)
(declare-fun input.context.mfa () Bool)
(assert (and true
     defined_input.context.mfa
     defined_input.context.ip
     defined_input.context.suspended
     defined_input.principal
     defined_input.action
     defined_input.resource
     defined_input.context.mfa
     defined_input.context.ip))
(assert (let ((a!1 (and (or (= input.principal "User::admins")
                    (= input.principal "User::alice"))
                (= input.action "Action::login")
                (= input.resource "App::portal"))))
(let ((a!2 (and a!1
                (= input.context.mfa true)
                (str.in_re input.context.ip (re.++ (str.to_re "10.") re.all))
                (not (and defined_input.principal
                          defined_input.action
                          defined_input.resource
                          defined_input.context.suspended
                          a!1
                          (= input.context.suspended true))))))
  (= (ite a!2 1 0) 1))))
