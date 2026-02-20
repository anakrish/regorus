(declare-fun defined_input.context.hour () Bool)
(declare-fun defined_input.resource.vip () Bool)
(declare-fun defined_input.resource () Bool)
(declare-fun defined_input.action () Bool)
(declare-fun defined_input.principal () Bool)
(declare-fun defined_input.context.device_trusted () Bool)
(declare-fun defined_input.context.emergency () Bool)
(declare-fun input.context.hour () Int)
(declare-fun input.context.emergency () Bool)
(declare-fun input.resource () String)
(declare-fun input.action () String)
(declare-fun input.resource.vip () Bool)
(declare-fun input.principal () String)
(declare-fun input.context.device_trusted () Bool)
(assert (and true
     defined_input.principal
     defined_input.context.hour
     defined_input.context.hour
     defined_input.context.device_trusted
     defined_input.resource.vip
     defined_input.context.hour
     defined_input.context.hour
     defined_input.context.emergency
     defined_input.context.hour
     defined_input.context.hour
     (and defined_input.principal defined_input.action defined_input.resource)
     defined_input.principal
     defined_input.context.hour
     defined_input.context.hour
     defined_input.context.device_trusted
     (and defined_input.principal defined_input.action defined_input.resource)
     defined_input.resource.vip
     defined_input.context.hour
     defined_input.context.hour))
(assert (let ((a!1 (= (ite (= input.principal "User::dr_jones")
                   "cardiology"
                   (ite (= input.principal "User::dr_smith") "oncology" ""))
              "oncology"))
      (a!3 (not (and defined_input.action
                     defined_input.resource
                     defined_input.context.emergency
                     defined_input.context.hour
                     defined_input.context.hour
                     true
                     (= input.action "Action::viewRecord")
                     (= input.resource "PatientRecord::chart-42")
                     (= input.context.emergency false)
                     (or (< input.context.hour 6) (> input.context.hour 22))))))
(let ((a!2 (or (and (or (= input.principal "Role::doctors")
                        (= input.principal "User::dr_jones")
                        (= input.principal "User::dr_smith"))
                    (= input.action "Action::viewRecord")
                    (= input.resource "PatientRecord::chart-42")
                    a!1
                    (>= input.context.hour 8)
                    (<= input.context.hour 18)
                    (= input.context.device_trusted true))
               (and (or (= input.principal "Role::nurses")
                        (= input.principal "User::nurse_amy"))
                    (= input.action "Action::viewRecord")
                    (= input.resource "PatientRecord::chart-42")
                    (= input.resource.vip false)
                    (>= input.context.hour 6)
                    (<= input.context.hour 20)))))
  (= (ite (and a!2 a!3) 1 0) 1))))
