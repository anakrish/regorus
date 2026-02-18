(declare-fun |defined_input.servers[1]| () Bool)
(declare-fun |input.networks[2].public| () Bool)
(declare-fun |defined_input.networks[2].public| () Bool)
(declare-fun |input.networks[2].id| () String)
(declare-fun |input.ports[2].network| () String)
(declare-fun |defined_input.networks[2].id| () Bool)
(declare-fun |defined_input.ports[2].network| () Bool)
(declare-fun |defined_input.networks[2]| () Bool)
(declare-fun |input.ports[2].id| () String)
(declare-fun |input.servers[1].ports[0]| () String)
(declare-fun |defined_input.servers[1].ports[0]| () Bool)
(declare-fun |input.servers[1].ports[2]| () String)
(declare-fun |defined_input.servers[1].ports[2]| () Bool)
(declare-fun |input.servers[1].ports[1]| () String)
(declare-fun |defined_input.servers[1].ports[1]| () Bool)
(declare-fun |defined_input.ports[2].id| () Bool)
(declare-fun |defined_input.servers[1].ports| () Bool)
(declare-fun |defined_input.ports[2]| () Bool)
(declare-fun |input.networks[1].public| () Bool)
(declare-fun |defined_input.networks[1].public| () Bool)
(declare-fun |input.networks[1].id| () String)
(declare-fun |defined_input.networks[1].id| () Bool)
(declare-fun |defined_input.networks[1]| () Bool)
(declare-fun |input.networks[0].public| () Bool)
(declare-fun |defined_input.networks[0].public| () Bool)
(declare-fun |input.networks[0].id| () String)
(declare-fun |defined_input.networks[0].id| () Bool)
(declare-fun |defined_input.networks[0]| () Bool)
(declare-fun |input.ports[1].network| () String)
(declare-fun |defined_input.ports[1].network| () Bool)
(declare-fun |input.ports[1].id| () String)
(declare-fun |defined_input.ports[1].id| () Bool)
(declare-fun |defined_input.ports[1]| () Bool)
(declare-fun |input.ports[0].network| () String)
(declare-fun |defined_input.ports[0].network| () Bool)
(declare-fun |input.ports[0].id| () String)
(declare-fun |defined_input.ports[0].id| () Bool)
(declare-fun |defined_input.ports[0]| () Bool)
(declare-fun |defined_input.servers[0]| () Bool)
(declare-fun |input.servers[0].ports[0]| () String)
(declare-fun |defined_input.servers[0].ports[0]| () Bool)
(declare-fun |input.servers[0].ports[1]| () String)
(declare-fun |defined_input.servers[0].ports[1]| () Bool)
(declare-fun |input.servers[0].ports[2]| () String)
(declare-fun |defined_input.servers[0].ports[2]| () Bool)
(declare-fun |defined_input.servers[0].ports| () Bool)
(declare-fun |defined_input.servers[2]| () Bool)
(declare-fun |input.servers[2].ports[1]| () String)
(declare-fun |defined_input.servers[2].ports[1]| () Bool)
(declare-fun |input.servers[2].ports[2]| () String)
(declare-fun |defined_input.servers[2].ports[2]| () Bool)
(declare-fun |input.servers[2].ports[0]| () String)
(declare-fun |defined_input.servers[2].ports[0]| () Bool)
(declare-fun |defined_input.servers[2].ports| () Bool)
(declare-fun |input.servers[0].id| () String)
(declare-fun |input.servers[1].id| () String)
(declare-fun |defined_input.servers[0].id| () Bool)
(declare-fun |input.servers[0].protocols[2]| () String)
(declare-fun |defined_input.servers[0].protocols[2]| () Bool)
(declare-fun |input.servers[0].protocols[0]| () String)
(declare-fun |defined_input.servers[0].protocols[0]| () Bool)
(declare-fun |input.servers[0].protocols[1]| () String)
(declare-fun |defined_input.servers[0].protocols[1]| () Bool)
(declare-fun |defined_input.servers[0].protocols| () Bool)
(declare-fun |defined_input.servers[1].id| () Bool)
(declare-fun |input.servers[1].protocols[0]| () String)
(declare-fun |defined_input.servers[1].protocols[0]| () Bool)
(declare-fun |input.servers[1].protocols[2]| () String)
(declare-fun |defined_input.servers[1].protocols[2]| () Bool)
(declare-fun |input.servers[1].protocols[1]| () String)
(declare-fun |defined_input.servers[1].protocols[1]| () Bool)
(declare-fun |defined_input.servers[1].protocols| () Bool)
(declare-fun |input.servers[2].id| () String)
(declare-fun |defined_input.servers[2].id| () Bool)
(declare-fun |input.servers[2].protocols[2]| () String)
(declare-fun |defined_input.servers[2].protocols[2]| () Bool)
(declare-fun |input.servers[2].protocols[1]| () String)
(declare-fun |defined_input.servers[2].protocols[1]| () Bool)
(declare-fun |input.servers[2].protocols[0]| () String)
(declare-fun |defined_input.servers[2].protocols[0]| () Bool)
(declare-fun |defined_input.servers[2].protocols| () Bool)
(declare-fun defined_input.servers () Bool)
(declare-fun defined_input.networks () Bool)
(declare-fun defined_input.ports () Bool)
(assert (let ((a!1 (and (and true |defined_input.servers[2]|)
                |defined_input.ports[0]|
                |defined_input.servers[2].ports|
                |defined_input.ports[0].id|
                (or (and |defined_input.servers[2].ports[0]|
                         (= |input.servers[2].ports[0]| |input.ports[0].id|))
                    (and |defined_input.servers[2].ports[2]|
                         (= |input.servers[2].ports[2]| |input.ports[0].id|))
                    (and |defined_input.servers[2].ports[1]|
                         (= |input.servers[2].ports[1]| |input.ports[0].id|)))))
      (a!2 (and (and true |defined_input.servers[2]|)
                |defined_input.ports[1]|
                |defined_input.servers[2].ports|
                |defined_input.ports[1].id|
                (or (and |defined_input.servers[2].ports[0]|
                         (= |input.servers[2].ports[0]| |input.ports[1].id|))
                    (and |defined_input.servers[2].ports[2]|
                         (= |input.servers[2].ports[2]| |input.ports[1].id|))
                    (and |defined_input.servers[2].ports[1]|
                         (= |input.servers[2].ports[1]| |input.ports[1].id|)))))
      (a!3 (and (and true |defined_input.servers[2]|)
                |defined_input.ports[2]|
                |defined_input.servers[2].ports|
                |defined_input.ports[2].id|
                (or (and |defined_input.servers[2].ports[0]|
                         (= |input.servers[2].ports[0]| |input.ports[2].id|))
                    (and |defined_input.servers[2].ports[2]|
                         (= |input.servers[2].ports[2]| |input.ports[2].id|))
                    (and |defined_input.servers[2].ports[1]|
                         (= |input.servers[2].ports[1]| |input.ports[2].id|)))))
      (a!5 (and (and true |defined_input.servers[0]|)
                |defined_input.ports[0]|
                |defined_input.servers[0].ports|
                |defined_input.ports[0].id|
                (or (and |defined_input.servers[0].ports[2]|
                         (= |input.servers[0].ports[2]| |input.ports[0].id|))
                    (and |defined_input.servers[0].ports[1]|
                         (= |input.servers[0].ports[1]| |input.ports[0].id|))
                    (and |defined_input.servers[0].ports[0]|
                         (= |input.servers[0].ports[0]| |input.ports[0].id|)))))
      (a!6 (and (and true |defined_input.servers[0]|)
                |defined_input.ports[1]|
                |defined_input.servers[0].ports|
                |defined_input.ports[1].id|
                (or (and |defined_input.servers[0].ports[2]|
                         (= |input.servers[0].ports[2]| |input.ports[1].id|))
                    (and |defined_input.servers[0].ports[1]|
                         (= |input.servers[0].ports[1]| |input.ports[1].id|))
                    (and |defined_input.servers[0].ports[0]|
                         (= |input.servers[0].ports[0]| |input.ports[1].id|)))))
      (a!7 (and (and true |defined_input.servers[0]|)
                |defined_input.ports[2]|
                |defined_input.servers[0].ports|
                |defined_input.ports[2].id|
                (or (and |defined_input.servers[0].ports[2]|
                         (= |input.servers[0].ports[2]| |input.ports[2].id|))
                    (and |defined_input.servers[0].ports[1]|
                         (= |input.servers[0].ports[1]| |input.ports[2].id|))
                    (and |defined_input.servers[0].ports[0]|
                         (= |input.servers[0].ports[0]| |input.ports[2].id|)))))
      (a!9 (and (and true |defined_input.servers[1]|)
                |defined_input.ports[0]|
                |defined_input.servers[1].ports|
                |defined_input.ports[0].id|
                (or (and |defined_input.servers[1].ports[1]|
                         (= |input.servers[1].ports[1]| |input.ports[0].id|))
                    (and |defined_input.servers[1].ports[2]|
                         (= |input.servers[1].ports[2]| |input.ports[0].id|))
                    (and |defined_input.servers[1].ports[0]|
                         (= |input.servers[1].ports[0]| |input.ports[0].id|)))))
      (a!10 (and (and true |defined_input.servers[1]|)
                 |defined_input.ports[1]|
                 |defined_input.servers[1].ports|
                 |defined_input.ports[1].id|
                 (or (and |defined_input.servers[1].ports[1]|
                          (= |input.servers[1].ports[1]| |input.ports[1].id|))
                     (and |defined_input.servers[1].ports[2]|
                          (= |input.servers[1].ports[2]| |input.ports[1].id|))
                     (and |defined_input.servers[1].ports[0]|
                          (= |input.servers[1].ports[0]| |input.ports[1].id|)))))
      (a!11 (and (and true |defined_input.servers[1]|)
                 |defined_input.ports[2]|
                 |defined_input.servers[1].ports|
                 |defined_input.ports[2].id|
                 (or (and |defined_input.servers[1].ports[1]|
                          (= |input.servers[1].ports[1]| |input.ports[2].id|))
                     (and |defined_input.servers[1].ports[2]|
                          (= |input.servers[1].ports[2]| |input.ports[2].id|))
                     (and |defined_input.servers[1].ports[0]|
                          (= |input.servers[1].ports[0]| |input.ports[2].id|))))))
(let ((a!4 (or (and a!1
                    |defined_input.networks[0]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[0].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[2]|)
               (and a!1
                    |defined_input.networks[1]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[0].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[2]|)
               (and a!1
                    |defined_input.networks[2]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[0].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[2]|)
               (and a!2
                    |defined_input.networks[0]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[1].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[2]|)
               (and a!2
                    |defined_input.networks[1]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[1].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[2]|)
               (and a!2
                    |defined_input.networks[2]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[1].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[2]|)
               (and a!3
                    |defined_input.networks[0]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[2].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[2]|)
               (and a!3
                    |defined_input.networks[1]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[2].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[2]|)
               (and a!3
                    |defined_input.networks[2]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[2].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[2]|)))
      (a!8 (or (and a!5
                    |defined_input.networks[0]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[0].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[0]|)
               (and a!5
                    |defined_input.networks[1]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[0].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[0]|)
               (and a!5
                    |defined_input.networks[2]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[0].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[0]|)
               (and a!6
                    |defined_input.networks[0]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[1].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[0]|)
               (and a!6
                    |defined_input.networks[1]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[1].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[0]|)
               (and a!6
                    |defined_input.networks[2]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[1].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[0]|)
               (and a!7
                    |defined_input.networks[0]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[2].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[0]|)
               (and a!7
                    |defined_input.networks[1]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[2].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[0]|)
               (and a!7
                    |defined_input.networks[2]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[2].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[0]|)))
      (a!12 (or (and a!9
                     |defined_input.networks[0]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[0].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[1]|)
                (and a!9
                     |defined_input.networks[1]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[0].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[1]|)
                (and a!9
                     |defined_input.networks[2]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[0].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[1]|)
                (and a!10
                     |defined_input.networks[0]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[1].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[1]|)
                (and a!10
                     |defined_input.networks[1]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[1].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[1]|)
                (and a!10
                     |defined_input.networks[2]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[1].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[1]|)
                (and a!11
                     |defined_input.networks[0]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[2].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[1]|)
                (and a!11
                     |defined_input.networks[1]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[2].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[1]|)
                (and a!11
                     |defined_input.networks[2]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[2].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[1]|))))
  (>= (+ 0 (ite a!4 1 0) (ite a!8 1 0) (ite a!12 1 0)) 0))))
(assert (let ((a!1 (and (and true |defined_input.servers[1]|)
                |defined_input.ports[0]|
                |defined_input.servers[1].ports|
                |defined_input.ports[0].id|
                (or (and |defined_input.servers[1].ports[1]|
                         (= |input.servers[1].ports[1]| |input.ports[0].id|))
                    (and |defined_input.servers[1].ports[2]|
                         (= |input.servers[1].ports[2]| |input.ports[0].id|))
                    (and |defined_input.servers[1].ports[0]|
                         (= |input.servers[1].ports[0]| |input.ports[0].id|)))))
      (a!2 (and |defined_input.servers[1].protocols|
                (or (and |defined_input.servers[1].protocols[1]|
                         (= |input.servers[1].protocols[1]| "http"))
                    (and |defined_input.servers[1].protocols[2]|
                         (= |input.servers[1].protocols[2]| "http"))
                    (and |defined_input.servers[1].protocols[0]|
                         (= |input.servers[1].protocols[0]| "http")))))
      (a!3 (and (and true |defined_input.servers[1]|)
                |defined_input.ports[1]|
                |defined_input.servers[1].ports|
                |defined_input.ports[1].id|
                (or (and |defined_input.servers[1].ports[1]|
                         (= |input.servers[1].ports[1]| |input.ports[1].id|))
                    (and |defined_input.servers[1].ports[2]|
                         (= |input.servers[1].ports[2]| |input.ports[1].id|))
                    (and |defined_input.servers[1].ports[0]|
                         (= |input.servers[1].ports[0]| |input.ports[1].id|)))))
      (a!4 (and (and true |defined_input.servers[1]|)
                |defined_input.ports[2]|
                |defined_input.servers[1].ports|
                |defined_input.ports[2].id|
                (or (and |defined_input.servers[1].ports[1]|
                         (= |input.servers[1].ports[1]| |input.ports[2].id|))
                    (and |defined_input.servers[1].ports[2]|
                         (= |input.servers[1].ports[2]| |input.ports[2].id|))
                    (and |defined_input.servers[1].ports[0]|
                         (= |input.servers[1].ports[0]| |input.ports[2].id|)))))
      (a!5 (and (and true |defined_input.servers[1]|)
                |defined_input.servers[1].protocols|
                (or (and |defined_input.servers[1].protocols[1]|
                         (= |input.servers[1].protocols[1]| "telnet"))
                    (and |defined_input.servers[1].protocols[2]|
                         (= |input.servers[1].protocols[2]| "telnet"))
                    (and |defined_input.servers[1].protocols[0]|
                         (= |input.servers[1].protocols[0]| "telnet")))
                |defined_input.servers[1].id|))
      (a!7 (and (and true |defined_input.servers[0]|)
                |defined_input.ports[0]|
                |defined_input.servers[0].ports|
                |defined_input.ports[0].id|
                (or (and |defined_input.servers[0].ports[2]|
                         (= |input.servers[0].ports[2]| |input.ports[0].id|))
                    (and |defined_input.servers[0].ports[1]|
                         (= |input.servers[0].ports[1]| |input.ports[0].id|))
                    (and |defined_input.servers[0].ports[0]|
                         (= |input.servers[0].ports[0]| |input.ports[0].id|)))))
      (a!8 (and |defined_input.servers[0].protocols|
                (or (and |defined_input.servers[0].protocols[1]|
                         (= |input.servers[0].protocols[1]| "http"))
                    (and |defined_input.servers[0].protocols[0]|
                         (= |input.servers[0].protocols[0]| "http"))
                    (and |defined_input.servers[0].protocols[2]|
                         (= |input.servers[0].protocols[2]| "http")))))
      (a!9 (and (and true |defined_input.servers[0]|)
                |defined_input.ports[1]|
                |defined_input.servers[0].ports|
                |defined_input.ports[1].id|
                (or (and |defined_input.servers[0].ports[2]|
                         (= |input.servers[0].ports[2]| |input.ports[1].id|))
                    (and |defined_input.servers[0].ports[1]|
                         (= |input.servers[0].ports[1]| |input.ports[1].id|))
                    (and |defined_input.servers[0].ports[0]|
                         (= |input.servers[0].ports[0]| |input.ports[1].id|)))))
      (a!10 (and (and true |defined_input.servers[0]|)
                 |defined_input.ports[2]|
                 |defined_input.servers[0].ports|
                 |defined_input.ports[2].id|
                 (or (and |defined_input.servers[0].ports[2]|
                          (= |input.servers[0].ports[2]| |input.ports[2].id|))
                     (and |defined_input.servers[0].ports[1]|
                          (= |input.servers[0].ports[1]| |input.ports[2].id|))
                     (and |defined_input.servers[0].ports[0]|
                          (= |input.servers[0].ports[0]| |input.ports[2].id|)))))
      (a!11 (and (and true |defined_input.servers[0]|)
                 |defined_input.servers[0].protocols|
                 (or (and |defined_input.servers[0].protocols[1]|
                          (= |input.servers[0].protocols[1]| "telnet"))
                     (and |defined_input.servers[0].protocols[0]|
                          (= |input.servers[0].protocols[0]| "telnet"))
                     (and |defined_input.servers[0].protocols[2]|
                          (= |input.servers[0].protocols[2]| "telnet")))
                 |defined_input.servers[0].id|)))
(let ((a!6 (or (and true
                    a!1
                    |defined_input.networks[0]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[0].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!1
                    |defined_input.networks[1]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[0].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!1
                    |defined_input.networks[2]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[0].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!3
                    |defined_input.networks[0]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[1].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!3
                    |defined_input.networks[1]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[1].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!3
                    |defined_input.networks[2]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[1].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!4
                    |defined_input.networks[0]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[2].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!4
                    |defined_input.networks[1]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[2].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!4
                    |defined_input.networks[2]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[2].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               a!5))
      (a!12 (or (and true
                     a!7
                     |defined_input.networks[0]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[0].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!7
                     |defined_input.networks[1]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[0].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!7
                     |defined_input.networks[2]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[0].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!9
                     |defined_input.networks[0]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[1].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!9
                     |defined_input.networks[1]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[1].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!9
                     |defined_input.networks[2]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[1].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!10
                     |defined_input.networks[0]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[2].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!10
                     |defined_input.networks[1]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[2].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!10
                     |defined_input.networks[2]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[2].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                a!11)))
  (=> (and a!6 a!12) (not (= |input.servers[1].id| |input.servers[0].id|))))))
(assert (let ((a!1 (and (and true |defined_input.servers[1]|)
                |defined_input.ports[0]|
                |defined_input.servers[1].ports|
                |defined_input.ports[0].id|
                (or (and |defined_input.servers[1].ports[1]|
                         (= |input.servers[1].ports[1]| |input.ports[0].id|))
                    (and |defined_input.servers[1].ports[2]|
                         (= |input.servers[1].ports[2]| |input.ports[0].id|))
                    (and |defined_input.servers[1].ports[0]|
                         (= |input.servers[1].ports[0]| |input.ports[0].id|)))))
      (a!2 (and |defined_input.servers[1].protocols|
                (or (and |defined_input.servers[1].protocols[1]|
                         (= |input.servers[1].protocols[1]| "http"))
                    (and |defined_input.servers[1].protocols[2]|
                         (= |input.servers[1].protocols[2]| "http"))
                    (and |defined_input.servers[1].protocols[0]|
                         (= |input.servers[1].protocols[0]| "http")))))
      (a!3 (and (and true |defined_input.servers[1]|)
                |defined_input.ports[1]|
                |defined_input.servers[1].ports|
                |defined_input.ports[1].id|
                (or (and |defined_input.servers[1].ports[1]|
                         (= |input.servers[1].ports[1]| |input.ports[1].id|))
                    (and |defined_input.servers[1].ports[2]|
                         (= |input.servers[1].ports[2]| |input.ports[1].id|))
                    (and |defined_input.servers[1].ports[0]|
                         (= |input.servers[1].ports[0]| |input.ports[1].id|)))))
      (a!4 (and (and true |defined_input.servers[1]|)
                |defined_input.ports[2]|
                |defined_input.servers[1].ports|
                |defined_input.ports[2].id|
                (or (and |defined_input.servers[1].ports[1]|
                         (= |input.servers[1].ports[1]| |input.ports[2].id|))
                    (and |defined_input.servers[1].ports[2]|
                         (= |input.servers[1].ports[2]| |input.ports[2].id|))
                    (and |defined_input.servers[1].ports[0]|
                         (= |input.servers[1].ports[0]| |input.ports[2].id|)))))
      (a!5 (and (and true |defined_input.servers[1]|)
                |defined_input.servers[1].protocols|
                (or (and |defined_input.servers[1].protocols[1]|
                         (= |input.servers[1].protocols[1]| "telnet"))
                    (and |defined_input.servers[1].protocols[2]|
                         (= |input.servers[1].protocols[2]| "telnet"))
                    (and |defined_input.servers[1].protocols[0]|
                         (= |input.servers[1].protocols[0]| "telnet")))
                |defined_input.servers[1].id|))
      (a!7 (and (and true |defined_input.servers[2]|)
                |defined_input.ports[0]|
                |defined_input.servers[2].ports|
                |defined_input.ports[0].id|
                (or (and |defined_input.servers[2].ports[0]|
                         (= |input.servers[2].ports[0]| |input.ports[0].id|))
                    (and |defined_input.servers[2].ports[2]|
                         (= |input.servers[2].ports[2]| |input.ports[0].id|))
                    (and |defined_input.servers[2].ports[1]|
                         (= |input.servers[2].ports[1]| |input.ports[0].id|)))))
      (a!8 (and |defined_input.servers[2].protocols|
                (or (and |defined_input.servers[2].protocols[0]|
                         (= |input.servers[2].protocols[0]| "http"))
                    (and |defined_input.servers[2].protocols[1]|
                         (= |input.servers[2].protocols[1]| "http"))
                    (and |defined_input.servers[2].protocols[2]|
                         (= |input.servers[2].protocols[2]| "http")))))
      (a!9 (and (and true |defined_input.servers[2]|)
                |defined_input.ports[1]|
                |defined_input.servers[2].ports|
                |defined_input.ports[1].id|
                (or (and |defined_input.servers[2].ports[0]|
                         (= |input.servers[2].ports[0]| |input.ports[1].id|))
                    (and |defined_input.servers[2].ports[2]|
                         (= |input.servers[2].ports[2]| |input.ports[1].id|))
                    (and |defined_input.servers[2].ports[1]|
                         (= |input.servers[2].ports[1]| |input.ports[1].id|)))))
      (a!10 (and (and true |defined_input.servers[2]|)
                 |defined_input.ports[2]|
                 |defined_input.servers[2].ports|
                 |defined_input.ports[2].id|
                 (or (and |defined_input.servers[2].ports[0]|
                          (= |input.servers[2].ports[0]| |input.ports[2].id|))
                     (and |defined_input.servers[2].ports[2]|
                          (= |input.servers[2].ports[2]| |input.ports[2].id|))
                     (and |defined_input.servers[2].ports[1]|
                          (= |input.servers[2].ports[1]| |input.ports[2].id|)))))
      (a!11 (and (and true |defined_input.servers[2]|)
                 |defined_input.servers[2].protocols|
                 (or (and |defined_input.servers[2].protocols[0]|
                          (= |input.servers[2].protocols[0]| "telnet"))
                     (and |defined_input.servers[2].protocols[1]|
                          (= |input.servers[2].protocols[1]| "telnet"))
                     (and |defined_input.servers[2].protocols[2]|
                          (= |input.servers[2].protocols[2]| "telnet")))
                 |defined_input.servers[2].id|)))
(let ((a!6 (or (and true
                    a!1
                    |defined_input.networks[0]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[0].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!1
                    |defined_input.networks[1]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[0].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!1
                    |defined_input.networks[2]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[0].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!3
                    |defined_input.networks[0]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[1].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!3
                    |defined_input.networks[1]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[1].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!3
                    |defined_input.networks[2]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[1].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!4
                    |defined_input.networks[0]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[2].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!4
                    |defined_input.networks[1]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[2].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!4
                    |defined_input.networks[2]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[2].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               a!5))
      (a!12 (or (and true
                     a!7
                     |defined_input.networks[0]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[0].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                (and true
                     a!7
                     |defined_input.networks[1]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[0].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                (and true
                     a!7
                     |defined_input.networks[2]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[0].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                (and true
                     a!9
                     |defined_input.networks[0]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[1].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                (and true
                     a!9
                     |defined_input.networks[1]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[1].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                (and true
                     a!9
                     |defined_input.networks[2]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[1].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                (and true
                     a!10
                     |defined_input.networks[0]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[2].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                (and true
                     a!10
                     |defined_input.networks[1]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[2].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                (and true
                     a!10
                     |defined_input.networks[2]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[2].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                a!11)))
  (=> (and a!6 a!12) (not (= |input.servers[1].id| |input.servers[2].id|))))))
(assert (let ((a!1 (and (and true |defined_input.servers[0]|)
                |defined_input.ports[0]|
                |defined_input.servers[0].ports|
                |defined_input.ports[0].id|
                (or (and |defined_input.servers[0].ports[2]|
                         (= |input.servers[0].ports[2]| |input.ports[0].id|))
                    (and |defined_input.servers[0].ports[1]|
                         (= |input.servers[0].ports[1]| |input.ports[0].id|))
                    (and |defined_input.servers[0].ports[0]|
                         (= |input.servers[0].ports[0]| |input.ports[0].id|)))))
      (a!2 (and |defined_input.servers[0].protocols|
                (or (and |defined_input.servers[0].protocols[1]|
                         (= |input.servers[0].protocols[1]| "http"))
                    (and |defined_input.servers[0].protocols[0]|
                         (= |input.servers[0].protocols[0]| "http"))
                    (and |defined_input.servers[0].protocols[2]|
                         (= |input.servers[0].protocols[2]| "http")))))
      (a!3 (and (and true |defined_input.servers[0]|)
                |defined_input.ports[1]|
                |defined_input.servers[0].ports|
                |defined_input.ports[1].id|
                (or (and |defined_input.servers[0].ports[2]|
                         (= |input.servers[0].ports[2]| |input.ports[1].id|))
                    (and |defined_input.servers[0].ports[1]|
                         (= |input.servers[0].ports[1]| |input.ports[1].id|))
                    (and |defined_input.servers[0].ports[0]|
                         (= |input.servers[0].ports[0]| |input.ports[1].id|)))))
      (a!4 (and (and true |defined_input.servers[0]|)
                |defined_input.ports[2]|
                |defined_input.servers[0].ports|
                |defined_input.ports[2].id|
                (or (and |defined_input.servers[0].ports[2]|
                         (= |input.servers[0].ports[2]| |input.ports[2].id|))
                    (and |defined_input.servers[0].ports[1]|
                         (= |input.servers[0].ports[1]| |input.ports[2].id|))
                    (and |defined_input.servers[0].ports[0]|
                         (= |input.servers[0].ports[0]| |input.ports[2].id|)))))
      (a!5 (and (and true |defined_input.servers[0]|)
                |defined_input.servers[0].protocols|
                (or (and |defined_input.servers[0].protocols[1]|
                         (= |input.servers[0].protocols[1]| "telnet"))
                    (and |defined_input.servers[0].protocols[0]|
                         (= |input.servers[0].protocols[0]| "telnet"))
                    (and |defined_input.servers[0].protocols[2]|
                         (= |input.servers[0].protocols[2]| "telnet")))
                |defined_input.servers[0].id|))
      (a!7 (and (and true |defined_input.servers[2]|)
                |defined_input.ports[0]|
                |defined_input.servers[2].ports|
                |defined_input.ports[0].id|
                (or (and |defined_input.servers[2].ports[0]|
                         (= |input.servers[2].ports[0]| |input.ports[0].id|))
                    (and |defined_input.servers[2].ports[2]|
                         (= |input.servers[2].ports[2]| |input.ports[0].id|))
                    (and |defined_input.servers[2].ports[1]|
                         (= |input.servers[2].ports[1]| |input.ports[0].id|)))))
      (a!8 (and |defined_input.servers[2].protocols|
                (or (and |defined_input.servers[2].protocols[0]|
                         (= |input.servers[2].protocols[0]| "http"))
                    (and |defined_input.servers[2].protocols[1]|
                         (= |input.servers[2].protocols[1]| "http"))
                    (and |defined_input.servers[2].protocols[2]|
                         (= |input.servers[2].protocols[2]| "http")))))
      (a!9 (and (and true |defined_input.servers[2]|)
                |defined_input.ports[1]|
                |defined_input.servers[2].ports|
                |defined_input.ports[1].id|
                (or (and |defined_input.servers[2].ports[0]|
                         (= |input.servers[2].ports[0]| |input.ports[1].id|))
                    (and |defined_input.servers[2].ports[2]|
                         (= |input.servers[2].ports[2]| |input.ports[1].id|))
                    (and |defined_input.servers[2].ports[1]|
                         (= |input.servers[2].ports[1]| |input.ports[1].id|)))))
      (a!10 (and (and true |defined_input.servers[2]|)
                 |defined_input.ports[2]|
                 |defined_input.servers[2].ports|
                 |defined_input.ports[2].id|
                 (or (and |defined_input.servers[2].ports[0]|
                          (= |input.servers[2].ports[0]| |input.ports[2].id|))
                     (and |defined_input.servers[2].ports[2]|
                          (= |input.servers[2].ports[2]| |input.ports[2].id|))
                     (and |defined_input.servers[2].ports[1]|
                          (= |input.servers[2].ports[1]| |input.ports[2].id|)))))
      (a!11 (and (and true |defined_input.servers[2]|)
                 |defined_input.servers[2].protocols|
                 (or (and |defined_input.servers[2].protocols[0]|
                          (= |input.servers[2].protocols[0]| "telnet"))
                     (and |defined_input.servers[2].protocols[1]|
                          (= |input.servers[2].protocols[1]| "telnet"))
                     (and |defined_input.servers[2].protocols[2]|
                          (= |input.servers[2].protocols[2]| "telnet")))
                 |defined_input.servers[2].id|)))
(let ((a!6 (or (and true
                    a!1
                    |defined_input.networks[0]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[0].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[0]|
                    |defined_input.servers[0]|
                    a!2
                    |defined_input.servers[0].id|)
               (and true
                    a!1
                    |defined_input.networks[1]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[0].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[0]|
                    |defined_input.servers[0]|
                    a!2
                    |defined_input.servers[0].id|)
               (and true
                    a!1
                    |defined_input.networks[2]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[0].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[0]|
                    |defined_input.servers[0]|
                    a!2
                    |defined_input.servers[0].id|)
               (and true
                    a!3
                    |defined_input.networks[0]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[1].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[0]|
                    |defined_input.servers[0]|
                    a!2
                    |defined_input.servers[0].id|)
               (and true
                    a!3
                    |defined_input.networks[1]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[1].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[0]|
                    |defined_input.servers[0]|
                    a!2
                    |defined_input.servers[0].id|)
               (and true
                    a!3
                    |defined_input.networks[2]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[1].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[0]|
                    |defined_input.servers[0]|
                    a!2
                    |defined_input.servers[0].id|)
               (and true
                    a!4
                    |defined_input.networks[0]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[2].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[0]|
                    |defined_input.servers[0]|
                    a!2
                    |defined_input.servers[0].id|)
               (and true
                    a!4
                    |defined_input.networks[1]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[2].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[0]|
                    |defined_input.servers[0]|
                    a!2
                    |defined_input.servers[0].id|)
               (and true
                    a!4
                    |defined_input.networks[2]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[2].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[0]|
                    |defined_input.servers[0]|
                    a!2
                    |defined_input.servers[0].id|)
               a!5))
      (a!12 (or (and true
                     a!7
                     |defined_input.networks[0]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[0].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                (and true
                     a!7
                     |defined_input.networks[1]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[0].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                (and true
                     a!7
                     |defined_input.networks[2]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[0].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                (and true
                     a!9
                     |defined_input.networks[0]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[1].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                (and true
                     a!9
                     |defined_input.networks[1]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[1].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                (and true
                     a!9
                     |defined_input.networks[2]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[1].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                (and true
                     a!10
                     |defined_input.networks[0]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[2].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                (and true
                     a!10
                     |defined_input.networks[1]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[2].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                (and true
                     a!10
                     |defined_input.networks[2]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[2].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!8
                     |defined_input.servers[2].id|)
                a!11)))
  (=> (and a!6 a!12) (not (= |input.servers[0].id| |input.servers[2].id|))))))
(assert (let ((a!1 (and (and true |defined_input.servers[1]|)
                |defined_input.ports[0]|
                |defined_input.servers[1].ports|
                |defined_input.ports[0].id|
                (or (and |defined_input.servers[1].ports[1]|
                         (= |input.servers[1].ports[1]| |input.ports[0].id|))
                    (and |defined_input.servers[1].ports[2]|
                         (= |input.servers[1].ports[2]| |input.ports[0].id|))
                    (and |defined_input.servers[1].ports[0]|
                         (= |input.servers[1].ports[0]| |input.ports[0].id|)))))
      (a!2 (and |defined_input.servers[1].protocols|
                (or (and |defined_input.servers[1].protocols[1]|
                         (= |input.servers[1].protocols[1]| "http"))
                    (and |defined_input.servers[1].protocols[2]|
                         (= |input.servers[1].protocols[2]| "http"))
                    (and |defined_input.servers[1].protocols[0]|
                         (= |input.servers[1].protocols[0]| "http")))))
      (a!3 (and (and true |defined_input.servers[1]|)
                |defined_input.ports[1]|
                |defined_input.servers[1].ports|
                |defined_input.ports[1].id|
                (or (and |defined_input.servers[1].ports[1]|
                         (= |input.servers[1].ports[1]| |input.ports[1].id|))
                    (and |defined_input.servers[1].ports[2]|
                         (= |input.servers[1].ports[2]| |input.ports[1].id|))
                    (and |defined_input.servers[1].ports[0]|
                         (= |input.servers[1].ports[0]| |input.ports[1].id|)))))
      (a!4 (and (and true |defined_input.servers[1]|)
                |defined_input.ports[2]|
                |defined_input.servers[1].ports|
                |defined_input.ports[2].id|
                (or (and |defined_input.servers[1].ports[1]|
                         (= |input.servers[1].ports[1]| |input.ports[2].id|))
                    (and |defined_input.servers[1].ports[2]|
                         (= |input.servers[1].ports[2]| |input.ports[2].id|))
                    (and |defined_input.servers[1].ports[0]|
                         (= |input.servers[1].ports[0]| |input.ports[2].id|)))))
      (a!5 (and (and true |defined_input.servers[1]|)
                |defined_input.servers[1].protocols|
                (or (and |defined_input.servers[1].protocols[1]|
                         (= |input.servers[1].protocols[1]| "telnet"))
                    (and |defined_input.servers[1].protocols[2]|
                         (= |input.servers[1].protocols[2]| "telnet"))
                    (and |defined_input.servers[1].protocols[0]|
                         (= |input.servers[1].protocols[0]| "telnet")))
                |defined_input.servers[1].id|))
      (a!7 (and (and true |defined_input.servers[0]|)
                |defined_input.ports[0]|
                |defined_input.servers[0].ports|
                |defined_input.ports[0].id|
                (or (and |defined_input.servers[0].ports[2]|
                         (= |input.servers[0].ports[2]| |input.ports[0].id|))
                    (and |defined_input.servers[0].ports[1]|
                         (= |input.servers[0].ports[1]| |input.ports[0].id|))
                    (and |defined_input.servers[0].ports[0]|
                         (= |input.servers[0].ports[0]| |input.ports[0].id|)))))
      (a!8 (and |defined_input.servers[0].protocols|
                (or (and |defined_input.servers[0].protocols[1]|
                         (= |input.servers[0].protocols[1]| "http"))
                    (and |defined_input.servers[0].protocols[0]|
                         (= |input.servers[0].protocols[0]| "http"))
                    (and |defined_input.servers[0].protocols[2]|
                         (= |input.servers[0].protocols[2]| "http")))))
      (a!9 (and (and true |defined_input.servers[0]|)
                |defined_input.ports[1]|
                |defined_input.servers[0].ports|
                |defined_input.ports[1].id|
                (or (and |defined_input.servers[0].ports[2]|
                         (= |input.servers[0].ports[2]| |input.ports[1].id|))
                    (and |defined_input.servers[0].ports[1]|
                         (= |input.servers[0].ports[1]| |input.ports[1].id|))
                    (and |defined_input.servers[0].ports[0]|
                         (= |input.servers[0].ports[0]| |input.ports[1].id|)))))
      (a!10 (and (and true |defined_input.servers[0]|)
                 |defined_input.ports[2]|
                 |defined_input.servers[0].ports|
                 |defined_input.ports[2].id|
                 (or (and |defined_input.servers[0].ports[2]|
                          (= |input.servers[0].ports[2]| |input.ports[2].id|))
                     (and |defined_input.servers[0].ports[1]|
                          (= |input.servers[0].ports[1]| |input.ports[2].id|))
                     (and |defined_input.servers[0].ports[0]|
                          (= |input.servers[0].ports[0]| |input.ports[2].id|)))))
      (a!11 (and (and true |defined_input.servers[0]|)
                 |defined_input.servers[0].protocols|
                 (or (and |defined_input.servers[0].protocols[1]|
                          (= |input.servers[0].protocols[1]| "telnet"))
                     (and |defined_input.servers[0].protocols[0]|
                          (= |input.servers[0].protocols[0]| "telnet"))
                     (and |defined_input.servers[0].protocols[2]|
                          (= |input.servers[0].protocols[2]| "telnet")))
                 |defined_input.servers[0].id|))
      (a!13 (and (and true |defined_input.servers[2]|)
                 |defined_input.ports[0]|
                 |defined_input.servers[2].ports|
                 |defined_input.ports[0].id|
                 (or (and |defined_input.servers[2].ports[0]|
                          (= |input.servers[2].ports[0]| |input.ports[0].id|))
                     (and |defined_input.servers[2].ports[2]|
                          (= |input.servers[2].ports[2]| |input.ports[0].id|))
                     (and |defined_input.servers[2].ports[1]|
                          (= |input.servers[2].ports[1]| |input.ports[0].id|)))))
      (a!14 (and |defined_input.servers[2].protocols|
                 (or (and |defined_input.servers[2].protocols[0]|
                          (= |input.servers[2].protocols[0]| "http"))
                     (and |defined_input.servers[2].protocols[1]|
                          (= |input.servers[2].protocols[1]| "http"))
                     (and |defined_input.servers[2].protocols[2]|
                          (= |input.servers[2].protocols[2]| "http")))))
      (a!15 (and (and true |defined_input.servers[2]|)
                 |defined_input.ports[1]|
                 |defined_input.servers[2].ports|
                 |defined_input.ports[1].id|
                 (or (and |defined_input.servers[2].ports[0]|
                          (= |input.servers[2].ports[0]| |input.ports[1].id|))
                     (and |defined_input.servers[2].ports[2]|
                          (= |input.servers[2].ports[2]| |input.ports[1].id|))
                     (and |defined_input.servers[2].ports[1]|
                          (= |input.servers[2].ports[1]| |input.ports[1].id|)))))
      (a!16 (and (and true |defined_input.servers[2]|)
                 |defined_input.ports[2]|
                 |defined_input.servers[2].ports|
                 |defined_input.ports[2].id|
                 (or (and |defined_input.servers[2].ports[0]|
                          (= |input.servers[2].ports[0]| |input.ports[2].id|))
                     (and |defined_input.servers[2].ports[2]|
                          (= |input.servers[2].ports[2]| |input.ports[2].id|))
                     (and |defined_input.servers[2].ports[1]|
                          (= |input.servers[2].ports[1]| |input.ports[2].id|)))))
      (a!17 (and (and true |defined_input.servers[2]|)
                 |defined_input.servers[2].protocols|
                 (or (and |defined_input.servers[2].protocols[0]|
                          (= |input.servers[2].protocols[0]| "telnet"))
                     (and |defined_input.servers[2].protocols[1]|
                          (= |input.servers[2].protocols[1]| "telnet"))
                     (and |defined_input.servers[2].protocols[2]|
                          (= |input.servers[2].protocols[2]| "telnet")))
                 |defined_input.servers[2].id|)))
(let ((a!6 (or (and true
                    a!1
                    |defined_input.networks[0]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[0].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!1
                    |defined_input.networks[1]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[0].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!1
                    |defined_input.networks[2]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[0].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!3
                    |defined_input.networks[0]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[1].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!3
                    |defined_input.networks[1]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[1].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!3
                    |defined_input.networks[2]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[1].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!4
                    |defined_input.networks[0]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[2].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!4
                    |defined_input.networks[1]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[2].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!4
                    |defined_input.networks[2]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[2].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               a!5))
      (a!12 (or (and true
                     a!7
                     |defined_input.networks[0]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[0].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!7
                     |defined_input.networks[1]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[0].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!7
                     |defined_input.networks[2]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[0].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!9
                     |defined_input.networks[0]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[1].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!9
                     |defined_input.networks[1]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[1].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!9
                     |defined_input.networks[2]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[1].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!10
                     |defined_input.networks[0]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[2].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!10
                     |defined_input.networks[1]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[2].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!10
                     |defined_input.networks[2]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[2].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                a!11))
      (a!18 (or (and true
                     a!13
                     |defined_input.networks[0]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[0].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                (and true
                     a!13
                     |defined_input.networks[1]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[0].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                (and true
                     a!13
                     |defined_input.networks[2]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[0].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                (and true
                     a!15
                     |defined_input.networks[0]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[1].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                (and true
                     a!15
                     |defined_input.networks[1]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[1].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                (and true
                     a!15
                     |defined_input.networks[2]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[1].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                (and true
                     a!16
                     |defined_input.networks[0]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[2].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                (and true
                     a!16
                     |defined_input.networks[1]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[2].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                (and true
                     a!16
                     |defined_input.networks[2]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[2].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                a!17)))
  (>= (+ 0 (ite a!6 1 0) (ite a!12 1 0) (ite a!18 1 0)) 0))))
(assert (or (= |input.networks[0].id| "net1")
    (= |input.networks[0].id| "net2")
    (= |input.networks[0].id| "net3")
    (= |input.networks[0].id| "net4")))
(assert |defined_input.networks[0].id|)
(assert |defined_input.networks[0].public|)
(assert (or (= |input.networks[1].id| "net1")
    (= |input.networks[1].id| "net2")
    (= |input.networks[1].id| "net3")
    (= |input.networks[1].id| "net4")))
(assert |defined_input.networks[1].id|)
(assert |defined_input.networks[1].public|)
(assert (or (= |input.networks[2].id| "net1")
    (= |input.networks[2].id| "net2")
    (= |input.networks[2].id| "net3")
    (= |input.networks[2].id| "net4")))
(assert |defined_input.networks[2].id|)
(assert |defined_input.networks[2].public|)
(assert |defined_input.networks[0].id|)
(assert |defined_input.networks[0].public|)
(assert (=> (and |defined_input.networks[0].id| |defined_input.networks[1].id|)
    (not (= |input.networks[0].id| |input.networks[1].id|))))
(assert (=> (and |defined_input.networks[0].id| |defined_input.networks[2].id|)
    (not (= |input.networks[0].id| |input.networks[2].id|))))
(assert (=> (and |defined_input.networks[1].id| |defined_input.networks[2].id|)
    (not (= |input.networks[1].id| |input.networks[2].id|))))
(assert (or (= |input.ports[0].id| "p1")
    (= |input.ports[0].id| "p2")
    (= |input.ports[0].id| "p3")))
(assert (or (= |input.ports[0].network| "net1")
    (= |input.ports[0].network| "net2")
    (= |input.ports[0].network| "net3")
    (= |input.ports[0].network| "net4")))
(assert |defined_input.ports[0].id|)
(assert |defined_input.ports[0].network|)
(assert (or (= |input.ports[1].id| "p1")
    (= |input.ports[1].id| "p2")
    (= |input.ports[1].id| "p3")))
(assert (or (= |input.ports[1].network| "net1")
    (= |input.ports[1].network| "net2")
    (= |input.ports[1].network| "net3")
    (= |input.ports[1].network| "net4")))
(assert |defined_input.ports[1].id|)
(assert |defined_input.ports[1].network|)
(assert (or (= |input.ports[2].id| "p1")
    (= |input.ports[2].id| "p2")
    (= |input.ports[2].id| "p3")))
(assert (or (= |input.ports[2].network| "net1")
    (= |input.ports[2].network| "net2")
    (= |input.ports[2].network| "net3")
    (= |input.ports[2].network| "net4")))
(assert |defined_input.ports[2].id|)
(assert |defined_input.ports[2].network|)
(assert |defined_input.ports[0].id|)
(assert |defined_input.ports[0].network|)
(assert (=> (and |defined_input.ports[0].id| |defined_input.ports[1].id|)
    (not (= |input.ports[0].id| |input.ports[1].id|))))
(assert (=> (and |defined_input.ports[0].id| |defined_input.ports[2].id|)
    (not (= |input.ports[0].id| |input.ports[2].id|))))
(assert (=> (and |defined_input.ports[1].id| |defined_input.ports[2].id|)
    (not (= |input.ports[1].id| |input.ports[2].id|))))
(assert (or (= |input.servers[0].id| "web")
    (= |input.servers[0].id| "db")
    (= |input.servers[0].id| "cache")
    (= |input.servers[0].id| "ci")
    (= |input.servers[0].id| "busybox")))
(assert (or (= |input.servers[0].ports[0]| "p1")
    (= |input.servers[0].ports[0]| "p2")
    (= |input.servers[0].ports[0]| "p3")))
(assert (or (= |input.servers[0].ports[1]| "p1")
    (= |input.servers[0].ports[1]| "p2")
    (= |input.servers[0].ports[1]| "p3")))
(assert (or (= |input.servers[0].ports[2]| "p1")
    (= |input.servers[0].ports[2]| "p2")
    (= |input.servers[0].ports[2]| "p3")))
(assert |defined_input.servers[0].ports[0]|)
(assert (=> (and |defined_input.servers[0].ports[0]|
         |defined_input.servers[0].ports[1]|)
    (not (= |input.servers[0].ports[0]| |input.servers[0].ports[1]|))))
(assert (=> (and |defined_input.servers[0].ports[0]|
         |defined_input.servers[0].ports[2]|)
    (not (= |input.servers[0].ports[0]| |input.servers[0].ports[2]|))))
(assert (=> (and |defined_input.servers[0].ports[1]|
         |defined_input.servers[0].ports[2]|)
    (not (= |input.servers[0].ports[1]| |input.servers[0].ports[2]|))))
(assert (or (= |input.servers[0].protocols[0]| "https")
    (= |input.servers[0].protocols[0]| "http")
    (= |input.servers[0].protocols[0]| "ssh")
    (= |input.servers[0].protocols[0]| "mysql")
    (= |input.servers[0].protocols[0]| "memcache")
    (= |input.servers[0].protocols[0]| "telnet")))
(assert (or (= |input.servers[0].protocols[1]| "https")
    (= |input.servers[0].protocols[1]| "http")
    (= |input.servers[0].protocols[1]| "ssh")
    (= |input.servers[0].protocols[1]| "mysql")
    (= |input.servers[0].protocols[1]| "memcache")
    (= |input.servers[0].protocols[1]| "telnet")))
(assert (or (= |input.servers[0].protocols[2]| "https")
    (= |input.servers[0].protocols[2]| "http")
    (= |input.servers[0].protocols[2]| "ssh")
    (= |input.servers[0].protocols[2]| "mysql")
    (= |input.servers[0].protocols[2]| "memcache")
    (= |input.servers[0].protocols[2]| "telnet")))
(assert |defined_input.servers[0].protocols[0]|)
(assert (=> (and |defined_input.servers[0].protocols[0]|
         |defined_input.servers[0].protocols[1]|)
    (not (= |input.servers[0].protocols[0]| |input.servers[0].protocols[1]|))))
(assert (=> (and |defined_input.servers[0].protocols[0]|
         |defined_input.servers[0].protocols[2]|)
    (not (= |input.servers[0].protocols[0]| |input.servers[0].protocols[2]|))))
(assert (=> (and |defined_input.servers[0].protocols[1]|
         |defined_input.servers[0].protocols[2]|)
    (not (= |input.servers[0].protocols[1]| |input.servers[0].protocols[2]|))))
(assert |defined_input.servers[0].id|)
(assert |defined_input.servers[0].protocols|)
(assert |defined_input.servers[0].ports|)
(assert (or (= |input.servers[1].id| "web")
    (= |input.servers[1].id| "db")
    (= |input.servers[1].id| "cache")
    (= |input.servers[1].id| "ci")
    (= |input.servers[1].id| "busybox")))
(assert (or (= |input.servers[1].ports[0]| "p1")
    (= |input.servers[1].ports[0]| "p2")
    (= |input.servers[1].ports[0]| "p3")))
(assert (or (= |input.servers[1].ports[1]| "p1")
    (= |input.servers[1].ports[1]| "p2")
    (= |input.servers[1].ports[1]| "p3")))
(assert (or (= |input.servers[1].ports[2]| "p1")
    (= |input.servers[1].ports[2]| "p2")
    (= |input.servers[1].ports[2]| "p3")))
(assert |defined_input.servers[1].ports[0]|)
(assert (=> (and |defined_input.servers[1].ports[0]|
         |defined_input.servers[1].ports[1]|)
    (not (= |input.servers[1].ports[0]| |input.servers[1].ports[1]|))))
(assert (=> (and |defined_input.servers[1].ports[0]|
         |defined_input.servers[1].ports[2]|)
    (not (= |input.servers[1].ports[0]| |input.servers[1].ports[2]|))))
(assert (=> (and |defined_input.servers[1].ports[1]|
         |defined_input.servers[1].ports[2]|)
    (not (= |input.servers[1].ports[1]| |input.servers[1].ports[2]|))))
(assert (or (= |input.servers[1].protocols[0]| "https")
    (= |input.servers[1].protocols[0]| "http")
    (= |input.servers[1].protocols[0]| "ssh")
    (= |input.servers[1].protocols[0]| "mysql")
    (= |input.servers[1].protocols[0]| "memcache")
    (= |input.servers[1].protocols[0]| "telnet")))
(assert (or (= |input.servers[1].protocols[1]| "https")
    (= |input.servers[1].protocols[1]| "http")
    (= |input.servers[1].protocols[1]| "ssh")
    (= |input.servers[1].protocols[1]| "mysql")
    (= |input.servers[1].protocols[1]| "memcache")
    (= |input.servers[1].protocols[1]| "telnet")))
(assert (or (= |input.servers[1].protocols[2]| "https")
    (= |input.servers[1].protocols[2]| "http")
    (= |input.servers[1].protocols[2]| "ssh")
    (= |input.servers[1].protocols[2]| "mysql")
    (= |input.servers[1].protocols[2]| "memcache")
    (= |input.servers[1].protocols[2]| "telnet")))
(assert |defined_input.servers[1].protocols[0]|)
(assert (=> (and |defined_input.servers[1].protocols[0]|
         |defined_input.servers[1].protocols[1]|)
    (not (= |input.servers[1].protocols[0]| |input.servers[1].protocols[1]|))))
(assert (=> (and |defined_input.servers[1].protocols[0]|
         |defined_input.servers[1].protocols[2]|)
    (not (= |input.servers[1].protocols[0]| |input.servers[1].protocols[2]|))))
(assert (=> (and |defined_input.servers[1].protocols[1]|
         |defined_input.servers[1].protocols[2]|)
    (not (= |input.servers[1].protocols[1]| |input.servers[1].protocols[2]|))))
(assert |defined_input.servers[1].id|)
(assert |defined_input.servers[1].protocols|)
(assert |defined_input.servers[1].ports|)
(assert (or (= |input.servers[2].id| "web")
    (= |input.servers[2].id| "db")
    (= |input.servers[2].id| "cache")
    (= |input.servers[2].id| "ci")
    (= |input.servers[2].id| "busybox")))
(assert (or (= |input.servers[2].ports[0]| "p1")
    (= |input.servers[2].ports[0]| "p2")
    (= |input.servers[2].ports[0]| "p3")))
(assert (or (= |input.servers[2].ports[1]| "p1")
    (= |input.servers[2].ports[1]| "p2")
    (= |input.servers[2].ports[1]| "p3")))
(assert (or (= |input.servers[2].ports[2]| "p1")
    (= |input.servers[2].ports[2]| "p2")
    (= |input.servers[2].ports[2]| "p3")))
(assert |defined_input.servers[2].ports[0]|)
(assert (=> (and |defined_input.servers[2].ports[0]|
         |defined_input.servers[2].ports[1]|)
    (not (= |input.servers[2].ports[0]| |input.servers[2].ports[1]|))))
(assert (=> (and |defined_input.servers[2].ports[0]|
         |defined_input.servers[2].ports[2]|)
    (not (= |input.servers[2].ports[0]| |input.servers[2].ports[2]|))))
(assert (=> (and |defined_input.servers[2].ports[1]|
         |defined_input.servers[2].ports[2]|)
    (not (= |input.servers[2].ports[1]| |input.servers[2].ports[2]|))))
(assert (or (= |input.servers[2].protocols[0]| "https")
    (= |input.servers[2].protocols[0]| "http")
    (= |input.servers[2].protocols[0]| "ssh")
    (= |input.servers[2].protocols[0]| "mysql")
    (= |input.servers[2].protocols[0]| "memcache")
    (= |input.servers[2].protocols[0]| "telnet")))
(assert (or (= |input.servers[2].protocols[1]| "https")
    (= |input.servers[2].protocols[1]| "http")
    (= |input.servers[2].protocols[1]| "ssh")
    (= |input.servers[2].protocols[1]| "mysql")
    (= |input.servers[2].protocols[1]| "memcache")
    (= |input.servers[2].protocols[1]| "telnet")))
(assert (or (= |input.servers[2].protocols[2]| "https")
    (= |input.servers[2].protocols[2]| "http")
    (= |input.servers[2].protocols[2]| "ssh")
    (= |input.servers[2].protocols[2]| "mysql")
    (= |input.servers[2].protocols[2]| "memcache")
    (= |input.servers[2].protocols[2]| "telnet")))
(assert |defined_input.servers[2].protocols[0]|)
(assert (=> (and |defined_input.servers[2].protocols[0]|
         |defined_input.servers[2].protocols[1]|)
    (not (= |input.servers[2].protocols[0]| |input.servers[2].protocols[1]|))))
(assert (=> (and |defined_input.servers[2].protocols[0]|
         |defined_input.servers[2].protocols[2]|)
    (not (= |input.servers[2].protocols[0]| |input.servers[2].protocols[2]|))))
(assert (=> (and |defined_input.servers[2].protocols[1]|
         |defined_input.servers[2].protocols[2]|)
    (not (= |input.servers[2].protocols[1]| |input.servers[2].protocols[2]|))))
(assert |defined_input.servers[2].id|)
(assert |defined_input.servers[2].protocols|)
(assert |defined_input.servers[2].ports|)
(assert |defined_input.servers[0].id|)
(assert |defined_input.servers[0].protocols|)
(assert |defined_input.servers[0].ports|)
(assert (=> (and |defined_input.servers[0].id| |defined_input.servers[1].id|)
    (not (= |input.servers[0].id| |input.servers[1].id|))))
(assert (=> (and |defined_input.servers[0].id| |defined_input.servers[2].id|)
    (not (= |input.servers[0].id| |input.servers[2].id|))))
(assert (=> (and |defined_input.servers[1].id| |defined_input.servers[2].id|)
    (not (= |input.servers[1].id| |input.servers[2].id|))))
(assert defined_input.servers)
(assert defined_input.networks)
(assert defined_input.ports)
(assert (and true true))
(assert (let ((a!1 (and (and true |defined_input.servers[1]|)
                |defined_input.ports[0]|
                |defined_input.servers[1].ports|
                |defined_input.ports[0].id|
                (or (and |defined_input.servers[1].ports[1]|
                         (= |input.servers[1].ports[1]| |input.ports[0].id|))
                    (and |defined_input.servers[1].ports[2]|
                         (= |input.servers[1].ports[2]| |input.ports[0].id|))
                    (and |defined_input.servers[1].ports[0]|
                         (= |input.servers[1].ports[0]| |input.ports[0].id|)))))
      (a!2 (and |defined_input.servers[1].protocols|
                (or (and |defined_input.servers[1].protocols[1]|
                         (= |input.servers[1].protocols[1]| "http"))
                    (and |defined_input.servers[1].protocols[2]|
                         (= |input.servers[1].protocols[2]| "http"))
                    (and |defined_input.servers[1].protocols[0]|
                         (= |input.servers[1].protocols[0]| "http")))))
      (a!3 (and (and true |defined_input.servers[1]|)
                |defined_input.ports[1]|
                |defined_input.servers[1].ports|
                |defined_input.ports[1].id|
                (or (and |defined_input.servers[1].ports[1]|
                         (= |input.servers[1].ports[1]| |input.ports[1].id|))
                    (and |defined_input.servers[1].ports[2]|
                         (= |input.servers[1].ports[2]| |input.ports[1].id|))
                    (and |defined_input.servers[1].ports[0]|
                         (= |input.servers[1].ports[0]| |input.ports[1].id|)))))
      (a!4 (and (and true |defined_input.servers[1]|)
                |defined_input.ports[2]|
                |defined_input.servers[1].ports|
                |defined_input.ports[2].id|
                (or (and |defined_input.servers[1].ports[1]|
                         (= |input.servers[1].ports[1]| |input.ports[2].id|))
                    (and |defined_input.servers[1].ports[2]|
                         (= |input.servers[1].ports[2]| |input.ports[2].id|))
                    (and |defined_input.servers[1].ports[0]|
                         (= |input.servers[1].ports[0]| |input.ports[2].id|)))))
      (a!5 (and (and true |defined_input.servers[1]|)
                |defined_input.servers[1].protocols|
                (or (and |defined_input.servers[1].protocols[1]|
                         (= |input.servers[1].protocols[1]| "telnet"))
                    (and |defined_input.servers[1].protocols[2]|
                         (= |input.servers[1].protocols[2]| "telnet"))
                    (and |defined_input.servers[1].protocols[0]|
                         (= |input.servers[1].protocols[0]| "telnet")))
                |defined_input.servers[1].id|))
      (a!7 (and (and true |defined_input.servers[0]|)
                |defined_input.ports[0]|
                |defined_input.servers[0].ports|
                |defined_input.ports[0].id|
                (or (and |defined_input.servers[0].ports[2]|
                         (= |input.servers[0].ports[2]| |input.ports[0].id|))
                    (and |defined_input.servers[0].ports[1]|
                         (= |input.servers[0].ports[1]| |input.ports[0].id|))
                    (and |defined_input.servers[0].ports[0]|
                         (= |input.servers[0].ports[0]| |input.ports[0].id|)))))
      (a!8 (and |defined_input.servers[0].protocols|
                (or (and |defined_input.servers[0].protocols[1]|
                         (= |input.servers[0].protocols[1]| "http"))
                    (and |defined_input.servers[0].protocols[0]|
                         (= |input.servers[0].protocols[0]| "http"))
                    (and |defined_input.servers[0].protocols[2]|
                         (= |input.servers[0].protocols[2]| "http")))))
      (a!9 (and (and true |defined_input.servers[0]|)
                |defined_input.ports[1]|
                |defined_input.servers[0].ports|
                |defined_input.ports[1].id|
                (or (and |defined_input.servers[0].ports[2]|
                         (= |input.servers[0].ports[2]| |input.ports[1].id|))
                    (and |defined_input.servers[0].ports[1]|
                         (= |input.servers[0].ports[1]| |input.ports[1].id|))
                    (and |defined_input.servers[0].ports[0]|
                         (= |input.servers[0].ports[0]| |input.ports[1].id|)))))
      (a!10 (and (and true |defined_input.servers[0]|)
                 |defined_input.ports[2]|
                 |defined_input.servers[0].ports|
                 |defined_input.ports[2].id|
                 (or (and |defined_input.servers[0].ports[2]|
                          (= |input.servers[0].ports[2]| |input.ports[2].id|))
                     (and |defined_input.servers[0].ports[1]|
                          (= |input.servers[0].ports[1]| |input.ports[2].id|))
                     (and |defined_input.servers[0].ports[0]|
                          (= |input.servers[0].ports[0]| |input.ports[2].id|)))))
      (a!11 (and (and true |defined_input.servers[0]|)
                 |defined_input.servers[0].protocols|
                 (or (and |defined_input.servers[0].protocols[1]|
                          (= |input.servers[0].protocols[1]| "telnet"))
                     (and |defined_input.servers[0].protocols[0]|
                          (= |input.servers[0].protocols[0]| "telnet"))
                     (and |defined_input.servers[0].protocols[2]|
                          (= |input.servers[0].protocols[2]| "telnet")))
                 |defined_input.servers[0].id|))
      (a!13 (and (and true |defined_input.servers[2]|)
                 |defined_input.ports[0]|
                 |defined_input.servers[2].ports|
                 |defined_input.ports[0].id|
                 (or (and |defined_input.servers[2].ports[0]|
                          (= |input.servers[2].ports[0]| |input.ports[0].id|))
                     (and |defined_input.servers[2].ports[2]|
                          (= |input.servers[2].ports[2]| |input.ports[0].id|))
                     (and |defined_input.servers[2].ports[1]|
                          (= |input.servers[2].ports[1]| |input.ports[0].id|)))))
      (a!14 (and |defined_input.servers[2].protocols|
                 (or (and |defined_input.servers[2].protocols[0]|
                          (= |input.servers[2].protocols[0]| "http"))
                     (and |defined_input.servers[2].protocols[1]|
                          (= |input.servers[2].protocols[1]| "http"))
                     (and |defined_input.servers[2].protocols[2]|
                          (= |input.servers[2].protocols[2]| "http")))))
      (a!15 (and (and true |defined_input.servers[2]|)
                 |defined_input.ports[1]|
                 |defined_input.servers[2].ports|
                 |defined_input.ports[1].id|
                 (or (and |defined_input.servers[2].ports[0]|
                          (= |input.servers[2].ports[0]| |input.ports[1].id|))
                     (and |defined_input.servers[2].ports[2]|
                          (= |input.servers[2].ports[2]| |input.ports[1].id|))
                     (and |defined_input.servers[2].ports[1]|
                          (= |input.servers[2].ports[1]| |input.ports[1].id|)))))
      (a!16 (and (and true |defined_input.servers[2]|)
                 |defined_input.ports[2]|
                 |defined_input.servers[2].ports|
                 |defined_input.ports[2].id|
                 (or (and |defined_input.servers[2].ports[0]|
                          (= |input.servers[2].ports[0]| |input.ports[2].id|))
                     (and |defined_input.servers[2].ports[2]|
                          (= |input.servers[2].ports[2]| |input.ports[2].id|))
                     (and |defined_input.servers[2].ports[1]|
                          (= |input.servers[2].ports[1]| |input.ports[2].id|)))))
      (a!17 (and (and true |defined_input.servers[2]|)
                 |defined_input.servers[2].protocols|
                 (or (and |defined_input.servers[2].protocols[0]|
                          (= |input.servers[2].protocols[0]| "telnet"))
                     (and |defined_input.servers[2].protocols[1]|
                          (= |input.servers[2].protocols[1]| "telnet"))
                     (and |defined_input.servers[2].protocols[2]|
                          (= |input.servers[2].protocols[2]| "telnet")))
                 |defined_input.servers[2].id|)))
(let ((a!6 (or (and true
                    a!1
                    |defined_input.networks[0]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[0].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!1
                    |defined_input.networks[1]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[0].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!1
                    |defined_input.networks[2]|
                    (and |defined_input.ports[0].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[0].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!3
                    |defined_input.networks[0]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[1].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!3
                    |defined_input.networks[1]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[1].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!3
                    |defined_input.networks[2]|
                    (and |defined_input.ports[1].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[1].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!4
                    |defined_input.networks[0]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[0].id|
                         (= |input.ports[2].network| |input.networks[0].id|))
                    (and |defined_input.networks[0].public|
                         |input.networks[0].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!4
                    |defined_input.networks[1]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[1].id|
                         (= |input.ports[2].network| |input.networks[1].id|))
                    (and |defined_input.networks[1].public|
                         |input.networks[1].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               (and true
                    a!4
                    |defined_input.networks[2]|
                    (and |defined_input.ports[2].network|
                         |defined_input.networks[2].id|
                         (= |input.ports[2].network| |input.networks[2].id|))
                    (and |defined_input.networks[2].public|
                         |input.networks[2].public|)
                    |defined_input.servers[1]|
                    |defined_input.servers[1]|
                    a!2
                    |defined_input.servers[1].id|)
               a!5))
      (a!12 (or (and true
                     a!7
                     |defined_input.networks[0]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[0].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!7
                     |defined_input.networks[1]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[0].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!7
                     |defined_input.networks[2]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[0].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!9
                     |defined_input.networks[0]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[1].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!9
                     |defined_input.networks[1]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[1].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!9
                     |defined_input.networks[2]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[1].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!10
                     |defined_input.networks[0]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[2].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!10
                     |defined_input.networks[1]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[2].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                (and true
                     a!10
                     |defined_input.networks[2]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[2].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[0]|
                     |defined_input.servers[0]|
                     a!8
                     |defined_input.servers[0].id|)
                a!11))
      (a!18 (or (and true
                     a!13
                     |defined_input.networks[0]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[0].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                (and true
                     a!13
                     |defined_input.networks[1]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[0].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                (and true
                     a!13
                     |defined_input.networks[2]|
                     (and |defined_input.ports[0].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[0].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                (and true
                     a!15
                     |defined_input.networks[0]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[1].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                (and true
                     a!15
                     |defined_input.networks[1]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[1].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                (and true
                     a!15
                     |defined_input.networks[2]|
                     (and |defined_input.ports[1].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[1].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                (and true
                     a!16
                     |defined_input.networks[0]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[0].id|
                          (= |input.ports[2].network| |input.networks[0].id|))
                     (and |defined_input.networks[0].public|
                          |input.networks[0].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                (and true
                     a!16
                     |defined_input.networks[1]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[1].id|
                          (= |input.ports[2].network| |input.networks[1].id|))
                     (and |defined_input.networks[1].public|
                          |input.networks[1].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                (and true
                     a!16
                     |defined_input.networks[2]|
                     (and |defined_input.ports[2].network|
                          |defined_input.networks[2].id|
                          (= |input.ports[2].network| |input.networks[2].id|))
                     (and |defined_input.networks[2].public|
                          |input.networks[2].public|)
                     |defined_input.servers[2]|
                     |defined_input.servers[2]|
                     a!14
                     |defined_input.servers[2].id|)
                a!17)))
(let ((a!19 (and true
                 (= (+ 0 (ite a!6 1 0) (ite a!12 1 0) (ite a!18 1 0)) 0)
                 true)))
  (= (ite a!19 true false) false)))))
