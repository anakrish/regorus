(declare-fun defined_input.resource () Bool)
(declare-fun defined_input.action () Bool)
(declare-fun defined_input.principal () Bool)
(declare-fun defined_input.context.suspended () Bool)
(declare-fun input.context.suspended () Bool)
(declare-fun input.resource () String)
(declare-fun input.action () String)
(declare-fun input.principal () String)
(assert (and true
     defined_input.context.suspended
     defined_input.principal
     defined_input.action
     defined_input.resource))
(assert (let ((a!1 (and (= input.principal "User::alice")
                (= input.action "Action::view")
                (= input.resource "File::report"))))
(let ((a!2 (and a!1
                true
                (not (and defined_input.principal
                          defined_input.action
                          defined_input.resource
                          defined_input.context.suspended
                          a!1
                          (= input.context.suspended true))))))
  (= (ite a!2 1 0) 1))))
