(declare-fun |defined_input.services[2]| () Bool)
(declare-fun |input.zones[2].dmz| () Bool)
(declare-fun |defined_input.zones[2].dmz| () Bool)
(declare-fun |input.services[2].zone_id| () String)
(declare-fun |input.zones[2].id| () String)
(declare-fun |defined_input.services[2].zone_id| () Bool)
(declare-fun |defined_input.zones[2].id| () Bool)
(declare-fun |defined_input.zones[2]| () Bool)
(declare-fun |input.zones[1].dmz| () Bool)
(declare-fun |defined_input.zones[1].dmz| () Bool)
(declare-fun |input.zones[1].id| () String)
(declare-fun |defined_input.zones[1].id| () Bool)
(declare-fun |defined_input.zones[1]| () Bool)
(declare-fun |input.zones[0].dmz| () Bool)
(declare-fun |defined_input.zones[0].dmz| () Bool)
(declare-fun |input.zones[0].id| () String)
(declare-fun |defined_input.zones[0].id| () Bool)
(declare-fun |defined_input.zones[0]| () Bool)
(declare-fun |defined_input.services[1]| () Bool)
(declare-fun |input.services[1].zone_id| () String)
(declare-fun |defined_input.services[1].zone_id| () Bool)
(declare-fun |defined_input.services[0]| () Bool)
(declare-fun |input.services[0].zone_id| () String)
(declare-fun |defined_input.services[0].zone_id| () Bool)
(declare-fun |input.services[2].name| () String)
(declare-fun |input.services[0].name| () String)
(declare-fun |defined_input.services[2].name| () Bool)
(declare-fun |input.connections[2].encrypted| () Bool)
(declare-fun |defined_input.connections[2].encrypted| () Bool)
(declare-fun |input.connections[2].source| () String)
(declare-fun |defined_input.connections[2].source| () Bool)
(declare-fun |defined_input.connections[2]| () Bool)
(declare-fun |input.services[2].handles_pii| () Bool)
(declare-fun |defined_input.services[2].handles_pii| () Bool)
(declare-fun |input.connections[1].encrypted| () Bool)
(declare-fun |defined_input.connections[1].encrypted| () Bool)
(declare-fun |input.connections[1].source| () String)
(declare-fun |defined_input.connections[1].source| () Bool)
(declare-fun |defined_input.connections[1]| () Bool)
(declare-fun |input.connections[0].encrypted| () Bool)
(declare-fun |defined_input.connections[0].encrypted| () Bool)
(declare-fun |input.connections[0].source| () String)
(declare-fun |defined_input.connections[0].source| () Bool)
(declare-fun |defined_input.connections[0]| () Bool)
(declare-fun |input.databases[2].internal| () Bool)
(declare-fun |defined_input.databases[2].internal| () Bool)
(declare-fun |input.connections[2].target| () String)
(declare-fun |input.databases[2].name| () String)
(declare-fun |defined_input.connections[2].target| () Bool)
(declare-fun |defined_input.databases[2].name| () Bool)
(declare-fun |defined_input.databases[2]| () Bool)
(declare-fun |input.databases[1].internal| () Bool)
(declare-fun |defined_input.databases[1].internal| () Bool)
(declare-fun |input.databases[1].name| () String)
(declare-fun |defined_input.databases[1].name| () Bool)
(declare-fun |defined_input.databases[1]| () Bool)
(declare-fun |input.databases[0].internal| () Bool)
(declare-fun |defined_input.databases[0].internal| () Bool)
(declare-fun |input.databases[0].name| () String)
(declare-fun |defined_input.databases[0].name| () Bool)
(declare-fun |defined_input.databases[0]| () Bool)
(declare-fun |input.connections[1].target| () String)
(declare-fun |defined_input.connections[1].target| () Bool)
(declare-fun |input.connections[0].target| () String)
(declare-fun |defined_input.connections[0].target| () Bool)
(declare-fun |defined_input.services[0].name| () Bool)
(declare-fun |input.services[0].handles_pii| () Bool)
(declare-fun |defined_input.services[0].handles_pii| () Bool)
(declare-fun |input.services[1].name| () String)
(declare-fun |defined_input.services[1].name| () Bool)
(declare-fun |input.services[1].handles_pii| () Bool)
(declare-fun |defined_input.services[1].handles_pii| () Bool)
(declare-fun defined_input.services () Bool)
(declare-fun defined_input.zones () Bool)
(declare-fun defined_input.connections () Bool)
(declare-fun defined_input.databases () Bool)
(assert (let ((a!1 (or (and (and true |defined_input.services[0]|)
                    |defined_input.zones[0]|
                    |defined_input.zones[0].id|
                    |defined_input.services[0].zone_id|
                    (= |input.zones[0].id| |input.services[0].zone_id|)
                    (and |defined_input.zones[0].dmz|
                         (= |input.zones[0].dmz| true))
                    |defined_input.services[0]|)
               (and (and true |defined_input.services[0]|)
                    |defined_input.zones[1]|
                    |defined_input.zones[1].id|
                    |defined_input.services[0].zone_id|
                    (= |input.zones[1].id| |input.services[0].zone_id|)
                    (and |defined_input.zones[1].dmz|
                         (= |input.zones[1].dmz| true))
                    |defined_input.services[0]|)
               (and (and true |defined_input.services[0]|)
                    |defined_input.zones[2]|
                    |defined_input.zones[2].id|
                    |defined_input.services[0].zone_id|
                    (= |input.zones[2].id| |input.services[0].zone_id|)
                    (and |defined_input.zones[2].dmz|
                         (= |input.zones[2].dmz| true))
                    |defined_input.services[0]|)))
      (a!2 (or (and (and true |defined_input.services[1]|)
                    |defined_input.zones[0]|
                    |defined_input.zones[0].id|
                    |defined_input.services[1].zone_id|
                    (= |input.zones[0].id| |input.services[1].zone_id|)
                    (and |defined_input.zones[0].dmz|
                         (= |input.zones[0].dmz| true))
                    |defined_input.services[1]|)
               (and (and true |defined_input.services[1]|)
                    |defined_input.zones[1]|
                    |defined_input.zones[1].id|
                    |defined_input.services[1].zone_id|
                    (= |input.zones[1].id| |input.services[1].zone_id|)
                    (and |defined_input.zones[1].dmz|
                         (= |input.zones[1].dmz| true))
                    |defined_input.services[1]|)
               (and (and true |defined_input.services[1]|)
                    |defined_input.zones[2]|
                    |defined_input.zones[2].id|
                    |defined_input.services[1].zone_id|
                    (= |input.zones[2].id| |input.services[1].zone_id|)
                    (and |defined_input.zones[2].dmz|
                         (= |input.zones[2].dmz| true))
                    |defined_input.services[1]|)))
      (a!3 (or (and (and true |defined_input.services[2]|)
                    |defined_input.zones[0]|
                    |defined_input.zones[0].id|
                    |defined_input.services[2].zone_id|
                    (= |input.zones[0].id| |input.services[2].zone_id|)
                    (and |defined_input.zones[0].dmz|
                         (= |input.zones[0].dmz| true))
                    |defined_input.services[2]|)
               (and (and true |defined_input.services[2]|)
                    |defined_input.zones[1]|
                    |defined_input.zones[1].id|
                    |defined_input.services[2].zone_id|
                    (= |input.zones[1].id| |input.services[2].zone_id|)
                    (and |defined_input.zones[1].dmz|
                         (= |input.zones[1].dmz| true))
                    |defined_input.services[2]|)
               (and (and true |defined_input.services[2]|)
                    |defined_input.zones[2]|
                    |defined_input.zones[2].id|
                    |defined_input.services[2].zone_id|
                    (= |input.zones[2].id| |input.services[2].zone_id|)
                    (and |defined_input.zones[2].dmz|
                         (= |input.zones[2].dmz| true))
                    |defined_input.services[2]|))))
  (>= (+ 0 (ite a!1 1 0) (ite a!2 1 0) (ite a!3 1 0)) 0)))
(assert (let ((a!1 (and true
                (and true |defined_input.services[0]|)
                |defined_input.zones[0]|
                |defined_input.zones[0].id|
                |defined_input.services[0].zone_id|
                (= |input.zones[0].id| |input.services[0].zone_id|)
                (and |defined_input.zones[0].dmz| (= |input.zones[0].dmz| true))
                |defined_input.services[0]|
                |defined_input.services[0]|))
      (a!11 (and true
                 (and true |defined_input.services[0]|)
                 |defined_input.zones[1]|
                 |defined_input.zones[1].id|
                 |defined_input.services[0].zone_id|
                 (= |input.zones[1].id| |input.services[0].zone_id|)
                 (and |defined_input.zones[1].dmz|
                      (= |input.zones[1].dmz| true))
                 |defined_input.services[0]|
                 |defined_input.services[0]|))
      (a!21 (and true
                 (and true |defined_input.services[0]|)
                 |defined_input.zones[2]|
                 |defined_input.zones[2].id|
                 |defined_input.services[0].zone_id|
                 (= |input.zones[2].id| |input.services[0].zone_id|)
                 (and |defined_input.zones[2].dmz|
                      (= |input.zones[2].dmz| true))
                 |defined_input.services[0]|
                 |defined_input.services[0]|))
      (a!32 (and true
                 (and true |defined_input.services[2]|)
                 |defined_input.zones[0]|
                 |defined_input.zones[0].id|
                 |defined_input.services[2].zone_id|
                 (= |input.zones[0].id| |input.services[2].zone_id|)
                 (and |defined_input.zones[0].dmz|
                      (= |input.zones[0].dmz| true))
                 |defined_input.services[2]|
                 |defined_input.services[2]|))
      (a!42 (and true
                 (and true |defined_input.services[2]|)
                 |defined_input.zones[1]|
                 |defined_input.zones[1].id|
                 |defined_input.services[2].zone_id|
                 (= |input.zones[1].id| |input.services[2].zone_id|)
                 (and |defined_input.zones[1].dmz|
                      (= |input.zones[1].dmz| true))
                 |defined_input.services[2]|
                 |defined_input.services[2]|))
      (a!52 (and true
                 (and true |defined_input.services[2]|)
                 |defined_input.zones[2]|
                 |defined_input.zones[2].id|
                 |defined_input.services[2].zone_id|
                 (= |input.zones[2].id| |input.services[2].zone_id|)
                 (and |defined_input.zones[2].dmz|
                      (= |input.zones[2].dmz| true))
                 |defined_input.services[2]|
                 |defined_input.services[2]|)))
(let ((a!2 (and (and a!1
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[0].name|
                          (= |input.connections[0].source|
                             |input.services[0].name|)))
                |defined_input.databases[0]|
                (and |defined_input.databases[0].name|
                     |defined_input.connections[0].target|
                     (= |input.databases[0].name| |input.connections[0].target|))
                (and |defined_input.databases[0].internal|
                     (= |input.databases[0].internal| true))
                |defined_input.services[0].name|))
      (a!3 (and (and a!1
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[0].name|
                          (= |input.connections[0].source|
                             |input.services[0].name|)))
                |defined_input.databases[1]|
                (and |defined_input.databases[1].name|
                     |defined_input.connections[0].target|
                     (= |input.databases[1].name| |input.connections[0].target|))
                (and |defined_input.databases[1].internal|
                     (= |input.databases[1].internal| true))
                |defined_input.services[0].name|))
      (a!4 (and (and a!1
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[0].name|
                          (= |input.connections[0].source|
                             |input.services[0].name|)))
                |defined_input.databases[2]|
                (and |defined_input.databases[2].name|
                     |defined_input.connections[0].target|
                     (= |input.databases[2].name| |input.connections[0].target|))
                (and |defined_input.databases[2].internal|
                     (= |input.databases[2].internal| true))
                |defined_input.services[0].name|))
      (a!5 (and (and a!1
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[0].name|
                          (= |input.connections[1].source|
                             |input.services[0].name|)))
                |defined_input.databases[0]|
                (and |defined_input.databases[0].name|
                     |defined_input.connections[1].target|
                     (= |input.databases[0].name| |input.connections[1].target|))
                (and |defined_input.databases[0].internal|
                     (= |input.databases[0].internal| true))
                |defined_input.services[0].name|))
      (a!6 (and (and a!1
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[0].name|
                          (= |input.connections[1].source|
                             |input.services[0].name|)))
                |defined_input.databases[1]|
                (and |defined_input.databases[1].name|
                     |defined_input.connections[1].target|
                     (= |input.databases[1].name| |input.connections[1].target|))
                (and |defined_input.databases[1].internal|
                     (= |input.databases[1].internal| true))
                |defined_input.services[0].name|))
      (a!7 (and (and a!1
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[0].name|
                          (= |input.connections[1].source|
                             |input.services[0].name|)))
                |defined_input.databases[2]|
                (and |defined_input.databases[2].name|
                     |defined_input.connections[1].target|
                     (= |input.databases[2].name| |input.connections[1].target|))
                (and |defined_input.databases[2].internal|
                     (= |input.databases[2].internal| true))
                |defined_input.services[0].name|))
      (a!8 (and (and a!1
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[0].name|
                          (= |input.connections[2].source|
                             |input.services[0].name|)))
                |defined_input.databases[0]|
                (and |defined_input.databases[0].name|
                     |defined_input.connections[2].target|
                     (= |input.databases[0].name| |input.connections[2].target|))
                (and |defined_input.databases[0].internal|
                     (= |input.databases[0].internal| true))
                |defined_input.services[0].name|))
      (a!9 (and (and a!1
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[0].name|
                          (= |input.connections[2].source|
                             |input.services[0].name|)))
                |defined_input.databases[1]|
                (and |defined_input.databases[1].name|
                     |defined_input.connections[2].target|
                     (= |input.databases[1].name| |input.connections[2].target|))
                (and |defined_input.databases[1].internal|
                     (= |input.databases[1].internal| true))
                |defined_input.services[0].name|))
      (a!10 (and (and a!1
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!12 (and (and a!11
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!13 (and (and a!11
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!14 (and (and a!11
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!15 (and (and a!11
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!16 (and (and a!11
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!17 (and (and a!11
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!18 (and (and a!11
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!19 (and (and a!11
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!20 (and (and a!11
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!22 (and (and a!21
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!23 (and (and a!21
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!24 (and (and a!21
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!25 (and (and a!21
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!26 (and (and a!21
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!27 (and (and a!21
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!28 (and (and a!21
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!29 (and (and a!21
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!30 (and (and a!21
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!33 (and (and a!32
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!34 (and (and a!32
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!35 (and (and a!32
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!36 (and (and a!32
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!37 (and (and a!32
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!38 (and (and a!32
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!39 (and (and a!32
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!40 (and (and a!32
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!41 (and (and a!32
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!43 (and (and a!42
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!44 (and (and a!42
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!45 (and (and a!42
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!46 (and (and a!42
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!47 (and (and a!42
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!48 (and (and a!42
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!49 (and (and a!42
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!50 (and (and a!42
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!51 (and (and a!42
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!53 (and (and a!52
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!54 (and (and a!52
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!55 (and (and a!52
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!56 (and (and a!52
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!57 (and (and a!52
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!58 (and (and a!52
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!59 (and (and a!52
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!60 (and (and a!52
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!61 (and (and a!52
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|)))
(let ((a!31 (or a!2
                a!3
                a!4
                a!5
                a!6
                a!7
                a!8
                a!9
                a!10
                a!12
                a!13
                a!14
                a!15
                a!16
                a!17
                a!18
                a!19
                a!20
                a!22
                a!23
                a!24
                a!25
                a!26
                a!27
                a!28
                a!29
                a!30
                (and (and (and true |defined_input.services[0]|)
                          |defined_input.services[0].handles_pii|
                          (= |input.services[0].handles_pii| true))
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[0].name|
                          (= |input.connections[0].source|
                             |input.services[0].name|))
                     (and |defined_input.connections[0].encrypted|
                          (= |input.connections[0].encrypted| false))
                     |defined_input.services[0].name|)
                (and (and (and true |defined_input.services[0]|)
                          |defined_input.services[0].handles_pii|
                          (= |input.services[0].handles_pii| true))
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[0].name|
                          (= |input.connections[1].source|
                             |input.services[0].name|))
                     (and |defined_input.connections[1].encrypted|
                          (= |input.connections[1].encrypted| false))
                     |defined_input.services[0].name|)
                (and (and (and true |defined_input.services[0]|)
                          |defined_input.services[0].handles_pii|
                          (= |input.services[0].handles_pii| true))
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[0].name|
                          (= |input.connections[2].source|
                             |input.services[0].name|))
                     (and |defined_input.connections[2].encrypted|
                          (= |input.connections[2].encrypted| false))
                     |defined_input.services[0].name|)))
      (a!62 (or a!33
                a!34
                a!35
                a!36
                a!37
                a!38
                a!39
                a!40
                a!41
                a!43
                a!44
                a!45
                a!46
                a!47
                a!48
                a!49
                a!50
                a!51
                a!53
                a!54
                a!55
                a!56
                a!57
                a!58
                a!59
                a!60
                a!61
                (and (and (and true |defined_input.services[2]|)
                          |defined_input.services[2].handles_pii|
                          (= |input.services[2].handles_pii| true))
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[2].name|
                          (= |input.connections[0].source|
                             |input.services[2].name|))
                     (and |defined_input.connections[0].encrypted|
                          (= |input.connections[0].encrypted| false))
                     |defined_input.services[2].name|)
                (and (and (and true |defined_input.services[2]|)
                          |defined_input.services[2].handles_pii|
                          (= |input.services[2].handles_pii| true))
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[2].name|
                          (= |input.connections[1].source|
                             |input.services[2].name|))
                     (and |defined_input.connections[1].encrypted|
                          (= |input.connections[1].encrypted| false))
                     |defined_input.services[2].name|)
                (and (and (and true |defined_input.services[2]|)
                          |defined_input.services[2].handles_pii|
                          (= |input.services[2].handles_pii| true))
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[2].name|
                          (= |input.connections[2].source|
                             |input.services[2].name|))
                     (and |defined_input.connections[2].encrypted|
                          (= |input.connections[2].encrypted| false))
                     |defined_input.services[2].name|))))
  (=> (and a!31 a!62)
      (not (= |input.services[0].name| |input.services[2].name|)))))))
(assert (let ((a!1 (and true
                (and true |defined_input.services[0]|)
                |defined_input.zones[0]|
                |defined_input.zones[0].id|
                |defined_input.services[0].zone_id|
                (= |input.zones[0].id| |input.services[0].zone_id|)
                (and |defined_input.zones[0].dmz| (= |input.zones[0].dmz| true))
                |defined_input.services[0]|
                |defined_input.services[0]|))
      (a!11 (and true
                 (and true |defined_input.services[0]|)
                 |defined_input.zones[1]|
                 |defined_input.zones[1].id|
                 |defined_input.services[0].zone_id|
                 (= |input.zones[1].id| |input.services[0].zone_id|)
                 (and |defined_input.zones[1].dmz|
                      (= |input.zones[1].dmz| true))
                 |defined_input.services[0]|
                 |defined_input.services[0]|))
      (a!21 (and true
                 (and true |defined_input.services[0]|)
                 |defined_input.zones[2]|
                 |defined_input.zones[2].id|
                 |defined_input.services[0].zone_id|
                 (= |input.zones[2].id| |input.services[0].zone_id|)
                 (and |defined_input.zones[2].dmz|
                      (= |input.zones[2].dmz| true))
                 |defined_input.services[0]|
                 |defined_input.services[0]|))
      (a!32 (and true
                 (and true |defined_input.services[1]|)
                 |defined_input.zones[0]|
                 |defined_input.zones[0].id|
                 |defined_input.services[1].zone_id|
                 (= |input.zones[0].id| |input.services[1].zone_id|)
                 (and |defined_input.zones[0].dmz|
                      (= |input.zones[0].dmz| true))
                 |defined_input.services[1]|
                 |defined_input.services[1]|))
      (a!42 (and true
                 (and true |defined_input.services[1]|)
                 |defined_input.zones[1]|
                 |defined_input.zones[1].id|
                 |defined_input.services[1].zone_id|
                 (= |input.zones[1].id| |input.services[1].zone_id|)
                 (and |defined_input.zones[1].dmz|
                      (= |input.zones[1].dmz| true))
                 |defined_input.services[1]|
                 |defined_input.services[1]|))
      (a!52 (and true
                 (and true |defined_input.services[1]|)
                 |defined_input.zones[2]|
                 |defined_input.zones[2].id|
                 |defined_input.services[1].zone_id|
                 (= |input.zones[2].id| |input.services[1].zone_id|)
                 (and |defined_input.zones[2].dmz|
                      (= |input.zones[2].dmz| true))
                 |defined_input.services[1]|
                 |defined_input.services[1]|)))
(let ((a!2 (and (and a!1
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[0].name|
                          (= |input.connections[0].source|
                             |input.services[0].name|)))
                |defined_input.databases[0]|
                (and |defined_input.databases[0].name|
                     |defined_input.connections[0].target|
                     (= |input.databases[0].name| |input.connections[0].target|))
                (and |defined_input.databases[0].internal|
                     (= |input.databases[0].internal| true))
                |defined_input.services[0].name|))
      (a!3 (and (and a!1
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[0].name|
                          (= |input.connections[0].source|
                             |input.services[0].name|)))
                |defined_input.databases[1]|
                (and |defined_input.databases[1].name|
                     |defined_input.connections[0].target|
                     (= |input.databases[1].name| |input.connections[0].target|))
                (and |defined_input.databases[1].internal|
                     (= |input.databases[1].internal| true))
                |defined_input.services[0].name|))
      (a!4 (and (and a!1
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[0].name|
                          (= |input.connections[0].source|
                             |input.services[0].name|)))
                |defined_input.databases[2]|
                (and |defined_input.databases[2].name|
                     |defined_input.connections[0].target|
                     (= |input.databases[2].name| |input.connections[0].target|))
                (and |defined_input.databases[2].internal|
                     (= |input.databases[2].internal| true))
                |defined_input.services[0].name|))
      (a!5 (and (and a!1
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[0].name|
                          (= |input.connections[1].source|
                             |input.services[0].name|)))
                |defined_input.databases[0]|
                (and |defined_input.databases[0].name|
                     |defined_input.connections[1].target|
                     (= |input.databases[0].name| |input.connections[1].target|))
                (and |defined_input.databases[0].internal|
                     (= |input.databases[0].internal| true))
                |defined_input.services[0].name|))
      (a!6 (and (and a!1
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[0].name|
                          (= |input.connections[1].source|
                             |input.services[0].name|)))
                |defined_input.databases[1]|
                (and |defined_input.databases[1].name|
                     |defined_input.connections[1].target|
                     (= |input.databases[1].name| |input.connections[1].target|))
                (and |defined_input.databases[1].internal|
                     (= |input.databases[1].internal| true))
                |defined_input.services[0].name|))
      (a!7 (and (and a!1
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[0].name|
                          (= |input.connections[1].source|
                             |input.services[0].name|)))
                |defined_input.databases[2]|
                (and |defined_input.databases[2].name|
                     |defined_input.connections[1].target|
                     (= |input.databases[2].name| |input.connections[1].target|))
                (and |defined_input.databases[2].internal|
                     (= |input.databases[2].internal| true))
                |defined_input.services[0].name|))
      (a!8 (and (and a!1
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[0].name|
                          (= |input.connections[2].source|
                             |input.services[0].name|)))
                |defined_input.databases[0]|
                (and |defined_input.databases[0].name|
                     |defined_input.connections[2].target|
                     (= |input.databases[0].name| |input.connections[2].target|))
                (and |defined_input.databases[0].internal|
                     (= |input.databases[0].internal| true))
                |defined_input.services[0].name|))
      (a!9 (and (and a!1
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[0].name|
                          (= |input.connections[2].source|
                             |input.services[0].name|)))
                |defined_input.databases[1]|
                (and |defined_input.databases[1].name|
                     |defined_input.connections[2].target|
                     (= |input.databases[1].name| |input.connections[2].target|))
                (and |defined_input.databases[1].internal|
                     (= |input.databases[1].internal| true))
                |defined_input.services[0].name|))
      (a!10 (and (and a!1
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!12 (and (and a!11
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!13 (and (and a!11
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!14 (and (and a!11
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!15 (and (and a!11
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!16 (and (and a!11
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!17 (and (and a!11
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!18 (and (and a!11
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!19 (and (and a!11
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!20 (and (and a!11
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!22 (and (and a!21
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!23 (and (and a!21
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!24 (and (and a!21
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!25 (and (and a!21
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!26 (and (and a!21
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!27 (and (and a!21
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!28 (and (and a!21
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!29 (and (and a!21
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!30 (and (and a!21
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!33 (and (and a!32
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!34 (and (and a!32
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!35 (and (and a!32
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!36 (and (and a!32
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!37 (and (and a!32
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!38 (and (and a!32
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!39 (and (and a!32
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!40 (and (and a!32
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!41 (and (and a!32
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!43 (and (and a!42
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!44 (and (and a!42
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!45 (and (and a!42
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!46 (and (and a!42
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!47 (and (and a!42
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!48 (and (and a!42
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!49 (and (and a!42
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!50 (and (and a!42
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!51 (and (and a!42
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!53 (and (and a!52
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!54 (and (and a!52
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!55 (and (and a!52
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!56 (and (and a!52
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!57 (and (and a!52
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!58 (and (and a!52
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!59 (and (and a!52
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!60 (and (and a!52
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!61 (and (and a!52
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|)))
(let ((a!31 (or a!2
                a!3
                a!4
                a!5
                a!6
                a!7
                a!8
                a!9
                a!10
                a!12
                a!13
                a!14
                a!15
                a!16
                a!17
                a!18
                a!19
                a!20
                a!22
                a!23
                a!24
                a!25
                a!26
                a!27
                a!28
                a!29
                a!30
                (and (and (and true |defined_input.services[0]|)
                          |defined_input.services[0].handles_pii|
                          (= |input.services[0].handles_pii| true))
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[0].name|
                          (= |input.connections[0].source|
                             |input.services[0].name|))
                     (and |defined_input.connections[0].encrypted|
                          (= |input.connections[0].encrypted| false))
                     |defined_input.services[0].name|)
                (and (and (and true |defined_input.services[0]|)
                          |defined_input.services[0].handles_pii|
                          (= |input.services[0].handles_pii| true))
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[0].name|
                          (= |input.connections[1].source|
                             |input.services[0].name|))
                     (and |defined_input.connections[1].encrypted|
                          (= |input.connections[1].encrypted| false))
                     |defined_input.services[0].name|)
                (and (and (and true |defined_input.services[0]|)
                          |defined_input.services[0].handles_pii|
                          (= |input.services[0].handles_pii| true))
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[0].name|
                          (= |input.connections[2].source|
                             |input.services[0].name|))
                     (and |defined_input.connections[2].encrypted|
                          (= |input.connections[2].encrypted| false))
                     |defined_input.services[0].name|)))
      (a!62 (or a!33
                a!34
                a!35
                a!36
                a!37
                a!38
                a!39
                a!40
                a!41
                a!43
                a!44
                a!45
                a!46
                a!47
                a!48
                a!49
                a!50
                a!51
                a!53
                a!54
                a!55
                a!56
                a!57
                a!58
                a!59
                a!60
                a!61
                (and (and (and true |defined_input.services[1]|)
                          |defined_input.services[1].handles_pii|
                          (= |input.services[1].handles_pii| true))
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[1].name|
                          (= |input.connections[0].source|
                             |input.services[1].name|))
                     (and |defined_input.connections[0].encrypted|
                          (= |input.connections[0].encrypted| false))
                     |defined_input.services[1].name|)
                (and (and (and true |defined_input.services[1]|)
                          |defined_input.services[1].handles_pii|
                          (= |input.services[1].handles_pii| true))
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[1].name|
                          (= |input.connections[1].source|
                             |input.services[1].name|))
                     (and |defined_input.connections[1].encrypted|
                          (= |input.connections[1].encrypted| false))
                     |defined_input.services[1].name|)
                (and (and (and true |defined_input.services[1]|)
                          |defined_input.services[1].handles_pii|
                          (= |input.services[1].handles_pii| true))
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[1].name|
                          (= |input.connections[2].source|
                             |input.services[1].name|))
                     (and |defined_input.connections[2].encrypted|
                          (= |input.connections[2].encrypted| false))
                     |defined_input.services[1].name|))))
  (=> (and a!31 a!62)
      (not (= |input.services[0].name| |input.services[1].name|)))))))
(assert (let ((a!1 (and true
                (and true |defined_input.services[2]|)
                |defined_input.zones[0]|
                |defined_input.zones[0].id|
                |defined_input.services[2].zone_id|
                (= |input.zones[0].id| |input.services[2].zone_id|)
                (and |defined_input.zones[0].dmz| (= |input.zones[0].dmz| true))
                |defined_input.services[2]|
                |defined_input.services[2]|))
      (a!11 (and true
                 (and true |defined_input.services[2]|)
                 |defined_input.zones[1]|
                 |defined_input.zones[1].id|
                 |defined_input.services[2].zone_id|
                 (= |input.zones[1].id| |input.services[2].zone_id|)
                 (and |defined_input.zones[1].dmz|
                      (= |input.zones[1].dmz| true))
                 |defined_input.services[2]|
                 |defined_input.services[2]|))
      (a!21 (and true
                 (and true |defined_input.services[2]|)
                 |defined_input.zones[2]|
                 |defined_input.zones[2].id|
                 |defined_input.services[2].zone_id|
                 (= |input.zones[2].id| |input.services[2].zone_id|)
                 (and |defined_input.zones[2].dmz|
                      (= |input.zones[2].dmz| true))
                 |defined_input.services[2]|
                 |defined_input.services[2]|))
      (a!32 (and true
                 (and true |defined_input.services[1]|)
                 |defined_input.zones[0]|
                 |defined_input.zones[0].id|
                 |defined_input.services[1].zone_id|
                 (= |input.zones[0].id| |input.services[1].zone_id|)
                 (and |defined_input.zones[0].dmz|
                      (= |input.zones[0].dmz| true))
                 |defined_input.services[1]|
                 |defined_input.services[1]|))
      (a!42 (and true
                 (and true |defined_input.services[1]|)
                 |defined_input.zones[1]|
                 |defined_input.zones[1].id|
                 |defined_input.services[1].zone_id|
                 (= |input.zones[1].id| |input.services[1].zone_id|)
                 (and |defined_input.zones[1].dmz|
                      (= |input.zones[1].dmz| true))
                 |defined_input.services[1]|
                 |defined_input.services[1]|))
      (a!52 (and true
                 (and true |defined_input.services[1]|)
                 |defined_input.zones[2]|
                 |defined_input.zones[2].id|
                 |defined_input.services[1].zone_id|
                 (= |input.zones[2].id| |input.services[1].zone_id|)
                 (and |defined_input.zones[2].dmz|
                      (= |input.zones[2].dmz| true))
                 |defined_input.services[1]|
                 |defined_input.services[1]|)))
(let ((a!2 (and (and a!1
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[2].name|
                          (= |input.connections[0].source|
                             |input.services[2].name|)))
                |defined_input.databases[0]|
                (and |defined_input.databases[0].name|
                     |defined_input.connections[0].target|
                     (= |input.databases[0].name| |input.connections[0].target|))
                (and |defined_input.databases[0].internal|
                     (= |input.databases[0].internal| true))
                |defined_input.services[2].name|))
      (a!3 (and (and a!1
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[2].name|
                          (= |input.connections[0].source|
                             |input.services[2].name|)))
                |defined_input.databases[1]|
                (and |defined_input.databases[1].name|
                     |defined_input.connections[0].target|
                     (= |input.databases[1].name| |input.connections[0].target|))
                (and |defined_input.databases[1].internal|
                     (= |input.databases[1].internal| true))
                |defined_input.services[2].name|))
      (a!4 (and (and a!1
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[2].name|
                          (= |input.connections[0].source|
                             |input.services[2].name|)))
                |defined_input.databases[2]|
                (and |defined_input.databases[2].name|
                     |defined_input.connections[0].target|
                     (= |input.databases[2].name| |input.connections[0].target|))
                (and |defined_input.databases[2].internal|
                     (= |input.databases[2].internal| true))
                |defined_input.services[2].name|))
      (a!5 (and (and a!1
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[2].name|
                          (= |input.connections[1].source|
                             |input.services[2].name|)))
                |defined_input.databases[0]|
                (and |defined_input.databases[0].name|
                     |defined_input.connections[1].target|
                     (= |input.databases[0].name| |input.connections[1].target|))
                (and |defined_input.databases[0].internal|
                     (= |input.databases[0].internal| true))
                |defined_input.services[2].name|))
      (a!6 (and (and a!1
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[2].name|
                          (= |input.connections[1].source|
                             |input.services[2].name|)))
                |defined_input.databases[1]|
                (and |defined_input.databases[1].name|
                     |defined_input.connections[1].target|
                     (= |input.databases[1].name| |input.connections[1].target|))
                (and |defined_input.databases[1].internal|
                     (= |input.databases[1].internal| true))
                |defined_input.services[2].name|))
      (a!7 (and (and a!1
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[2].name|
                          (= |input.connections[1].source|
                             |input.services[2].name|)))
                |defined_input.databases[2]|
                (and |defined_input.databases[2].name|
                     |defined_input.connections[1].target|
                     (= |input.databases[2].name| |input.connections[1].target|))
                (and |defined_input.databases[2].internal|
                     (= |input.databases[2].internal| true))
                |defined_input.services[2].name|))
      (a!8 (and (and a!1
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[2].name|
                          (= |input.connections[2].source|
                             |input.services[2].name|)))
                |defined_input.databases[0]|
                (and |defined_input.databases[0].name|
                     |defined_input.connections[2].target|
                     (= |input.databases[0].name| |input.connections[2].target|))
                (and |defined_input.databases[0].internal|
                     (= |input.databases[0].internal| true))
                |defined_input.services[2].name|))
      (a!9 (and (and a!1
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[2].name|
                          (= |input.connections[2].source|
                             |input.services[2].name|)))
                |defined_input.databases[1]|
                (and |defined_input.databases[1].name|
                     |defined_input.connections[2].target|
                     (= |input.databases[1].name| |input.connections[2].target|))
                (and |defined_input.databases[1].internal|
                     (= |input.databases[1].internal| true))
                |defined_input.services[2].name|))
      (a!10 (and (and a!1
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!12 (and (and a!11
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!13 (and (and a!11
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!14 (and (and a!11
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!15 (and (and a!11
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!16 (and (and a!11
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!17 (and (and a!11
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!18 (and (and a!11
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!19 (and (and a!11
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!20 (and (and a!11
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!22 (and (and a!21
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!23 (and (and a!21
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!24 (and (and a!21
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!25 (and (and a!21
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!26 (and (and a!21
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!27 (and (and a!21
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!28 (and (and a!21
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!29 (and (and a!21
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!30 (and (and a!21
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!33 (and (and a!32
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!34 (and (and a!32
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!35 (and (and a!32
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!36 (and (and a!32
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!37 (and (and a!32
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!38 (and (and a!32
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!39 (and (and a!32
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!40 (and (and a!32
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!41 (and (and a!32
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!43 (and (and a!42
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!44 (and (and a!42
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!45 (and (and a!42
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!46 (and (and a!42
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!47 (and (and a!42
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!48 (and (and a!42
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!49 (and (and a!42
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!50 (and (and a!42
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!51 (and (and a!42
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!53 (and (and a!52
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!54 (and (and a!52
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!55 (and (and a!52
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!56 (and (and a!52
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!57 (and (and a!52
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!58 (and (and a!52
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!59 (and (and a!52
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!60 (and (and a!52
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!61 (and (and a!52
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|)))
(let ((a!31 (or a!2
                a!3
                a!4
                a!5
                a!6
                a!7
                a!8
                a!9
                a!10
                a!12
                a!13
                a!14
                a!15
                a!16
                a!17
                a!18
                a!19
                a!20
                a!22
                a!23
                a!24
                a!25
                a!26
                a!27
                a!28
                a!29
                a!30
                (and (and (and true |defined_input.services[2]|)
                          |defined_input.services[2].handles_pii|
                          (= |input.services[2].handles_pii| true))
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[2].name|
                          (= |input.connections[0].source|
                             |input.services[2].name|))
                     (and |defined_input.connections[0].encrypted|
                          (= |input.connections[0].encrypted| false))
                     |defined_input.services[2].name|)
                (and (and (and true |defined_input.services[2]|)
                          |defined_input.services[2].handles_pii|
                          (= |input.services[2].handles_pii| true))
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[2].name|
                          (= |input.connections[1].source|
                             |input.services[2].name|))
                     (and |defined_input.connections[1].encrypted|
                          (= |input.connections[1].encrypted| false))
                     |defined_input.services[2].name|)
                (and (and (and true |defined_input.services[2]|)
                          |defined_input.services[2].handles_pii|
                          (= |input.services[2].handles_pii| true))
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[2].name|
                          (= |input.connections[2].source|
                             |input.services[2].name|))
                     (and |defined_input.connections[2].encrypted|
                          (= |input.connections[2].encrypted| false))
                     |defined_input.services[2].name|)))
      (a!62 (or a!33
                a!34
                a!35
                a!36
                a!37
                a!38
                a!39
                a!40
                a!41
                a!43
                a!44
                a!45
                a!46
                a!47
                a!48
                a!49
                a!50
                a!51
                a!53
                a!54
                a!55
                a!56
                a!57
                a!58
                a!59
                a!60
                a!61
                (and (and (and true |defined_input.services[1]|)
                          |defined_input.services[1].handles_pii|
                          (= |input.services[1].handles_pii| true))
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[1].name|
                          (= |input.connections[0].source|
                             |input.services[1].name|))
                     (and |defined_input.connections[0].encrypted|
                          (= |input.connections[0].encrypted| false))
                     |defined_input.services[1].name|)
                (and (and (and true |defined_input.services[1]|)
                          |defined_input.services[1].handles_pii|
                          (= |input.services[1].handles_pii| true))
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[1].name|
                          (= |input.connections[1].source|
                             |input.services[1].name|))
                     (and |defined_input.connections[1].encrypted|
                          (= |input.connections[1].encrypted| false))
                     |defined_input.services[1].name|)
                (and (and (and true |defined_input.services[1]|)
                          |defined_input.services[1].handles_pii|
                          (= |input.services[1].handles_pii| true))
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[1].name|
                          (= |input.connections[2].source|
                             |input.services[1].name|))
                     (and |defined_input.connections[2].encrypted|
                          (= |input.connections[2].encrypted| false))
                     |defined_input.services[1].name|))))
  (=> (and a!31 a!62)
      (not (= |input.services[2].name| |input.services[1].name|)))))))
(assert (let ((a!1 (and true
                (and true |defined_input.services[0]|)
                |defined_input.zones[0]|
                |defined_input.zones[0].id|
                |defined_input.services[0].zone_id|
                (= |input.zones[0].id| |input.services[0].zone_id|)
                (and |defined_input.zones[0].dmz| (= |input.zones[0].dmz| true))
                |defined_input.services[0]|
                |defined_input.services[0]|))
      (a!11 (and true
                 (and true |defined_input.services[0]|)
                 |defined_input.zones[1]|
                 |defined_input.zones[1].id|
                 |defined_input.services[0].zone_id|
                 (= |input.zones[1].id| |input.services[0].zone_id|)
                 (and |defined_input.zones[1].dmz|
                      (= |input.zones[1].dmz| true))
                 |defined_input.services[0]|
                 |defined_input.services[0]|))
      (a!21 (and true
                 (and true |defined_input.services[0]|)
                 |defined_input.zones[2]|
                 |defined_input.zones[2].id|
                 |defined_input.services[0].zone_id|
                 (= |input.zones[2].id| |input.services[0].zone_id|)
                 (and |defined_input.zones[2].dmz|
                      (= |input.zones[2].dmz| true))
                 |defined_input.services[0]|
                 |defined_input.services[0]|))
      (a!32 (and true
                 (and true |defined_input.services[2]|)
                 |defined_input.zones[0]|
                 |defined_input.zones[0].id|
                 |defined_input.services[2].zone_id|
                 (= |input.zones[0].id| |input.services[2].zone_id|)
                 (and |defined_input.zones[0].dmz|
                      (= |input.zones[0].dmz| true))
                 |defined_input.services[2]|
                 |defined_input.services[2]|))
      (a!42 (and true
                 (and true |defined_input.services[2]|)
                 |defined_input.zones[1]|
                 |defined_input.zones[1].id|
                 |defined_input.services[2].zone_id|
                 (= |input.zones[1].id| |input.services[2].zone_id|)
                 (and |defined_input.zones[1].dmz|
                      (= |input.zones[1].dmz| true))
                 |defined_input.services[2]|
                 |defined_input.services[2]|))
      (a!52 (and true
                 (and true |defined_input.services[2]|)
                 |defined_input.zones[2]|
                 |defined_input.zones[2].id|
                 |defined_input.services[2].zone_id|
                 (= |input.zones[2].id| |input.services[2].zone_id|)
                 (and |defined_input.zones[2].dmz|
                      (= |input.zones[2].dmz| true))
                 |defined_input.services[2]|
                 |defined_input.services[2]|))
      (a!63 (and true
                 (and true |defined_input.services[1]|)
                 |defined_input.zones[0]|
                 |defined_input.zones[0].id|
                 |defined_input.services[1].zone_id|
                 (= |input.zones[0].id| |input.services[1].zone_id|)
                 (and |defined_input.zones[0].dmz|
                      (= |input.zones[0].dmz| true))
                 |defined_input.services[1]|
                 |defined_input.services[1]|))
      (a!73 (and true
                 (and true |defined_input.services[1]|)
                 |defined_input.zones[1]|
                 |defined_input.zones[1].id|
                 |defined_input.services[1].zone_id|
                 (= |input.zones[1].id| |input.services[1].zone_id|)
                 (and |defined_input.zones[1].dmz|
                      (= |input.zones[1].dmz| true))
                 |defined_input.services[1]|
                 |defined_input.services[1]|))
      (a!83 (and true
                 (and true |defined_input.services[1]|)
                 |defined_input.zones[2]|
                 |defined_input.zones[2].id|
                 |defined_input.services[1].zone_id|
                 (= |input.zones[2].id| |input.services[1].zone_id|)
                 (and |defined_input.zones[2].dmz|
                      (= |input.zones[2].dmz| true))
                 |defined_input.services[1]|
                 |defined_input.services[1]|)))
(let ((a!2 (and (and a!1
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[0].name|
                          (= |input.connections[0].source|
                             |input.services[0].name|)))
                |defined_input.databases[0]|
                (and |defined_input.databases[0].name|
                     |defined_input.connections[0].target|
                     (= |input.databases[0].name| |input.connections[0].target|))
                (and |defined_input.databases[0].internal|
                     (= |input.databases[0].internal| true))
                |defined_input.services[0].name|))
      (a!3 (and (and a!1
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[0].name|
                          (= |input.connections[0].source|
                             |input.services[0].name|)))
                |defined_input.databases[1]|
                (and |defined_input.databases[1].name|
                     |defined_input.connections[0].target|
                     (= |input.databases[1].name| |input.connections[0].target|))
                (and |defined_input.databases[1].internal|
                     (= |input.databases[1].internal| true))
                |defined_input.services[0].name|))
      (a!4 (and (and a!1
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[0].name|
                          (= |input.connections[0].source|
                             |input.services[0].name|)))
                |defined_input.databases[2]|
                (and |defined_input.databases[2].name|
                     |defined_input.connections[0].target|
                     (= |input.databases[2].name| |input.connections[0].target|))
                (and |defined_input.databases[2].internal|
                     (= |input.databases[2].internal| true))
                |defined_input.services[0].name|))
      (a!5 (and (and a!1
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[0].name|
                          (= |input.connections[1].source|
                             |input.services[0].name|)))
                |defined_input.databases[0]|
                (and |defined_input.databases[0].name|
                     |defined_input.connections[1].target|
                     (= |input.databases[0].name| |input.connections[1].target|))
                (and |defined_input.databases[0].internal|
                     (= |input.databases[0].internal| true))
                |defined_input.services[0].name|))
      (a!6 (and (and a!1
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[0].name|
                          (= |input.connections[1].source|
                             |input.services[0].name|)))
                |defined_input.databases[1]|
                (and |defined_input.databases[1].name|
                     |defined_input.connections[1].target|
                     (= |input.databases[1].name| |input.connections[1].target|))
                (and |defined_input.databases[1].internal|
                     (= |input.databases[1].internal| true))
                |defined_input.services[0].name|))
      (a!7 (and (and a!1
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[0].name|
                          (= |input.connections[1].source|
                             |input.services[0].name|)))
                |defined_input.databases[2]|
                (and |defined_input.databases[2].name|
                     |defined_input.connections[1].target|
                     (= |input.databases[2].name| |input.connections[1].target|))
                (and |defined_input.databases[2].internal|
                     (= |input.databases[2].internal| true))
                |defined_input.services[0].name|))
      (a!8 (and (and a!1
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[0].name|
                          (= |input.connections[2].source|
                             |input.services[0].name|)))
                |defined_input.databases[0]|
                (and |defined_input.databases[0].name|
                     |defined_input.connections[2].target|
                     (= |input.databases[0].name| |input.connections[2].target|))
                (and |defined_input.databases[0].internal|
                     (= |input.databases[0].internal| true))
                |defined_input.services[0].name|))
      (a!9 (and (and a!1
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[0].name|
                          (= |input.connections[2].source|
                             |input.services[0].name|)))
                |defined_input.databases[1]|
                (and |defined_input.databases[1].name|
                     |defined_input.connections[2].target|
                     (= |input.databases[1].name| |input.connections[2].target|))
                (and |defined_input.databases[1].internal|
                     (= |input.databases[1].internal| true))
                |defined_input.services[0].name|))
      (a!10 (and (and a!1
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!12 (and (and a!11
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!13 (and (and a!11
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!14 (and (and a!11
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!15 (and (and a!11
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!16 (and (and a!11
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!17 (and (and a!11
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!18 (and (and a!11
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!19 (and (and a!11
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!20 (and (and a!11
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!22 (and (and a!21
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!23 (and (and a!21
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!24 (and (and a!21
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!25 (and (and a!21
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!26 (and (and a!21
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!27 (and (and a!21
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!28 (and (and a!21
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!29 (and (and a!21
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!30 (and (and a!21
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!33 (and (and a!32
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!34 (and (and a!32
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!35 (and (and a!32
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!36 (and (and a!32
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!37 (and (and a!32
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!38 (and (and a!32
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!39 (and (and a!32
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!40 (and (and a!32
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!41 (and (and a!32
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!43 (and (and a!42
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!44 (and (and a!42
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!45 (and (and a!42
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!46 (and (and a!42
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!47 (and (and a!42
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!48 (and (and a!42
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!49 (and (and a!42
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!50 (and (and a!42
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!51 (and (and a!42
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!53 (and (and a!52
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!54 (and (and a!52
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!55 (and (and a!52
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!56 (and (and a!52
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!57 (and (and a!52
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!58 (and (and a!52
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!59 (and (and a!52
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!60 (and (and a!52
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!61 (and (and a!52
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!64 (and (and a!63
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!65 (and (and a!63
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!66 (and (and a!63
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!67 (and (and a!63
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!68 (and (and a!63
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!69 (and (and a!63
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!70 (and (and a!63
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!71 (and (and a!63
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!72 (and (and a!63
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!74 (and (and a!73
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!75 (and (and a!73
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!76 (and (and a!73
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!77 (and (and a!73
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!78 (and (and a!73
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!79 (and (and a!73
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!80 (and (and a!73
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!81 (and (and a!73
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!82 (and (and a!73
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!84 (and (and a!83
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!85 (and (and a!83
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!86 (and (and a!83
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!87 (and (and a!83
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!88 (and (and a!83
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!89 (and (and a!83
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!90 (and (and a!83
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!91 (and (and a!83
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!92 (and (and a!83
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|)))
(let ((a!31 (or a!2
                a!3
                a!4
                a!5
                a!6
                a!7
                a!8
                a!9
                a!10
                a!12
                a!13
                a!14
                a!15
                a!16
                a!17
                a!18
                a!19
                a!20
                a!22
                a!23
                a!24
                a!25
                a!26
                a!27
                a!28
                a!29
                a!30
                (and (and (and true |defined_input.services[0]|)
                          |defined_input.services[0].handles_pii|
                          (= |input.services[0].handles_pii| true))
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[0].name|
                          (= |input.connections[0].source|
                             |input.services[0].name|))
                     (and |defined_input.connections[0].encrypted|
                          (= |input.connections[0].encrypted| false))
                     |defined_input.services[0].name|)
                (and (and (and true |defined_input.services[0]|)
                          |defined_input.services[0].handles_pii|
                          (= |input.services[0].handles_pii| true))
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[0].name|
                          (= |input.connections[1].source|
                             |input.services[0].name|))
                     (and |defined_input.connections[1].encrypted|
                          (= |input.connections[1].encrypted| false))
                     |defined_input.services[0].name|)
                (and (and (and true |defined_input.services[0]|)
                          |defined_input.services[0].handles_pii|
                          (= |input.services[0].handles_pii| true))
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[0].name|
                          (= |input.connections[2].source|
                             |input.services[0].name|))
                     (and |defined_input.connections[2].encrypted|
                          (= |input.connections[2].encrypted| false))
                     |defined_input.services[0].name|)))
      (a!62 (or a!33
                a!34
                a!35
                a!36
                a!37
                a!38
                a!39
                a!40
                a!41
                a!43
                a!44
                a!45
                a!46
                a!47
                a!48
                a!49
                a!50
                a!51
                a!53
                a!54
                a!55
                a!56
                a!57
                a!58
                a!59
                a!60
                a!61
                (and (and (and true |defined_input.services[2]|)
                          |defined_input.services[2].handles_pii|
                          (= |input.services[2].handles_pii| true))
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[2].name|
                          (= |input.connections[0].source|
                             |input.services[2].name|))
                     (and |defined_input.connections[0].encrypted|
                          (= |input.connections[0].encrypted| false))
                     |defined_input.services[2].name|)
                (and (and (and true |defined_input.services[2]|)
                          |defined_input.services[2].handles_pii|
                          (= |input.services[2].handles_pii| true))
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[2].name|
                          (= |input.connections[1].source|
                             |input.services[2].name|))
                     (and |defined_input.connections[1].encrypted|
                          (= |input.connections[1].encrypted| false))
                     |defined_input.services[2].name|)
                (and (and (and true |defined_input.services[2]|)
                          |defined_input.services[2].handles_pii|
                          (= |input.services[2].handles_pii| true))
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[2].name|
                          (= |input.connections[2].source|
                             |input.services[2].name|))
                     (and |defined_input.connections[2].encrypted|
                          (= |input.connections[2].encrypted| false))
                     |defined_input.services[2].name|)))
      (a!93 (or a!64
                a!65
                a!66
                a!67
                a!68
                a!69
                a!70
                a!71
                a!72
                a!74
                a!75
                a!76
                a!77
                a!78
                a!79
                a!80
                a!81
                a!82
                a!84
                a!85
                a!86
                a!87
                a!88
                a!89
                a!90
                a!91
                a!92
                (and (and (and true |defined_input.services[1]|)
                          |defined_input.services[1].handles_pii|
                          (= |input.services[1].handles_pii| true))
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[1].name|
                          (= |input.connections[0].source|
                             |input.services[1].name|))
                     (and |defined_input.connections[0].encrypted|
                          (= |input.connections[0].encrypted| false))
                     |defined_input.services[1].name|)
                (and (and (and true |defined_input.services[1]|)
                          |defined_input.services[1].handles_pii|
                          (= |input.services[1].handles_pii| true))
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[1].name|
                          (= |input.connections[1].source|
                             |input.services[1].name|))
                     (and |defined_input.connections[1].encrypted|
                          (= |input.connections[1].encrypted| false))
                     |defined_input.services[1].name|)
                (and (and (and true |defined_input.services[1]|)
                          |defined_input.services[1].handles_pii|
                          (= |input.services[1].handles_pii| true))
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[1].name|
                          (= |input.connections[2].source|
                             |input.services[1].name|))
                     (and |defined_input.connections[2].encrypted|
                          (= |input.connections[2].encrypted| false))
                     |defined_input.services[1].name|))))
  (>= (+ 0 (ite a!31 1 0) (ite a!62 1 0) (ite a!93 1 0)) 0)))))
(assert (or (= |input.connections[0].source| "frontend")
    (= |input.connections[0].source| "payment")
    (= |input.connections[0].source| "inventory")))
(assert (or (= |input.connections[0].target| "frontend")
    (= |input.connections[0].target| "payment")
    (= |input.connections[0].target| "inventory")
    (= |input.connections[0].target| "userdb")
    (= |input.connections[0].target| "orderdb")))
(assert |defined_input.connections[0].source|)
(assert |defined_input.connections[0].target|)
(assert |defined_input.connections[0].encrypted|)
(assert (or (= |input.connections[1].source| "frontend")
    (= |input.connections[1].source| "payment")
    (= |input.connections[1].source| "inventory")))
(assert (or (= |input.connections[1].target| "frontend")
    (= |input.connections[1].target| "payment")
    (= |input.connections[1].target| "inventory")
    (= |input.connections[1].target| "userdb")
    (= |input.connections[1].target| "orderdb")))
(assert |defined_input.connections[1].source|)
(assert |defined_input.connections[1].target|)
(assert |defined_input.connections[1].encrypted|)
(assert (or (= |input.connections[2].source| "frontend")
    (= |input.connections[2].source| "payment")
    (= |input.connections[2].source| "inventory")))
(assert (or (= |input.connections[2].target| "frontend")
    (= |input.connections[2].target| "payment")
    (= |input.connections[2].target| "inventory")
    (= |input.connections[2].target| "userdb")
    (= |input.connections[2].target| "orderdb")))
(assert |defined_input.connections[2].source|)
(assert |defined_input.connections[2].target|)
(assert |defined_input.connections[2].encrypted|)
(assert |defined_input.connections[0].source|)
(assert |defined_input.connections[0].target|)
(assert |defined_input.connections[0].encrypted|)
(assert (or (= |input.databases[0].name| "userdb")
    (= |input.databases[0].name| "orderdb")))
(assert |defined_input.databases[0].name|)
(assert |defined_input.databases[0].internal|)
(assert (or (= |input.databases[1].name| "userdb")
    (= |input.databases[1].name| "orderdb")))
(assert |defined_input.databases[1].name|)
(assert |defined_input.databases[1].internal|)
(assert |defined_input.databases[0].name|)
(assert |defined_input.databases[0].internal|)
(assert (=> (and |defined_input.databases[0].name| |defined_input.databases[1].name|)
    (not (= |input.databases[0].name| |input.databases[1].name|))))
(assert (or (= |input.services[0].name| "frontend")
    (= |input.services[0].name| "payment")
    (= |input.services[0].name| "inventory")))
(assert (or (= |input.services[0].zone_id| "dmz")
    (= |input.services[0].zone_id| "internal")
    (= |input.services[0].zone_id| "restricted")))
(assert |defined_input.services[0].name|)
(assert |defined_input.services[0].zone_id|)
(assert |defined_input.services[0].handles_pii|)
(assert (or (= |input.services[1].name| "frontend")
    (= |input.services[1].name| "payment")
    (= |input.services[1].name| "inventory")))
(assert (or (= |input.services[1].zone_id| "dmz")
    (= |input.services[1].zone_id| "internal")
    (= |input.services[1].zone_id| "restricted")))
(assert |defined_input.services[1].name|)
(assert |defined_input.services[1].zone_id|)
(assert |defined_input.services[1].handles_pii|)
(assert (or (= |input.services[2].name| "frontend")
    (= |input.services[2].name| "payment")
    (= |input.services[2].name| "inventory")))
(assert (or (= |input.services[2].zone_id| "dmz")
    (= |input.services[2].zone_id| "internal")
    (= |input.services[2].zone_id| "restricted")))
(assert |defined_input.services[2].name|)
(assert |defined_input.services[2].zone_id|)
(assert |defined_input.services[2].handles_pii|)
(assert |defined_input.services[0].name|)
(assert |defined_input.services[0].zone_id|)
(assert |defined_input.services[0].handles_pii|)
(assert (=> (and |defined_input.services[0].name| |defined_input.services[1].name|)
    (not (= |input.services[0].name| |input.services[1].name|))))
(assert (=> (and |defined_input.services[0].name| |defined_input.services[2].name|)
    (not (= |input.services[0].name| |input.services[2].name|))))
(assert (=> (and |defined_input.services[1].name| |defined_input.services[2].name|)
    (not (= |input.services[1].name| |input.services[2].name|))))
(assert (or (= |input.zones[0].id| "dmz")
    (= |input.zones[0].id| "internal")
    (= |input.zones[0].id| "restricted")))
(assert |defined_input.zones[0].id|)
(assert |defined_input.zones[0].dmz|)
(assert (or (= |input.zones[1].id| "dmz")
    (= |input.zones[1].id| "internal")
    (= |input.zones[1].id| "restricted")))
(assert |defined_input.zones[1].id|)
(assert |defined_input.zones[1].dmz|)
(assert (or (= |input.zones[2].id| "dmz")
    (= |input.zones[2].id| "internal")
    (= |input.zones[2].id| "restricted")))
(assert |defined_input.zones[2].id|)
(assert |defined_input.zones[2].dmz|)
(assert |defined_input.zones[0].id|)
(assert |defined_input.zones[0].dmz|)
(assert (=> (and |defined_input.zones[0].id| |defined_input.zones[1].id|)
    (not (= |input.zones[0].id| |input.zones[1].id|))))
(assert (=> (and |defined_input.zones[0].id| |defined_input.zones[2].id|)
    (not (= |input.zones[0].id| |input.zones[2].id|))))
(assert (=> (and |defined_input.zones[1].id| |defined_input.zones[2].id|)
    (not (= |input.zones[1].id| |input.zones[2].id|))))
(assert defined_input.services)
(assert defined_input.zones)
(assert defined_input.connections)
(assert defined_input.databases)
(assert (and true true))
(assert (let ((a!1 (and true
                (and true |defined_input.services[0]|)
                |defined_input.zones[0]|
                |defined_input.zones[0].id|
                |defined_input.services[0].zone_id|
                (= |input.zones[0].id| |input.services[0].zone_id|)
                (and |defined_input.zones[0].dmz| (= |input.zones[0].dmz| true))
                |defined_input.services[0]|
                |defined_input.services[0]|))
      (a!11 (and true
                 (and true |defined_input.services[0]|)
                 |defined_input.zones[1]|
                 |defined_input.zones[1].id|
                 |defined_input.services[0].zone_id|
                 (= |input.zones[1].id| |input.services[0].zone_id|)
                 (and |defined_input.zones[1].dmz|
                      (= |input.zones[1].dmz| true))
                 |defined_input.services[0]|
                 |defined_input.services[0]|))
      (a!21 (and true
                 (and true |defined_input.services[0]|)
                 |defined_input.zones[2]|
                 |defined_input.zones[2].id|
                 |defined_input.services[0].zone_id|
                 (= |input.zones[2].id| |input.services[0].zone_id|)
                 (and |defined_input.zones[2].dmz|
                      (= |input.zones[2].dmz| true))
                 |defined_input.services[0]|
                 |defined_input.services[0]|))
      (a!32 (and true
                 (and true |defined_input.services[2]|)
                 |defined_input.zones[0]|
                 |defined_input.zones[0].id|
                 |defined_input.services[2].zone_id|
                 (= |input.zones[0].id| |input.services[2].zone_id|)
                 (and |defined_input.zones[0].dmz|
                      (= |input.zones[0].dmz| true))
                 |defined_input.services[2]|
                 |defined_input.services[2]|))
      (a!42 (and true
                 (and true |defined_input.services[2]|)
                 |defined_input.zones[1]|
                 |defined_input.zones[1].id|
                 |defined_input.services[2].zone_id|
                 (= |input.zones[1].id| |input.services[2].zone_id|)
                 (and |defined_input.zones[1].dmz|
                      (= |input.zones[1].dmz| true))
                 |defined_input.services[2]|
                 |defined_input.services[2]|))
      (a!52 (and true
                 (and true |defined_input.services[2]|)
                 |defined_input.zones[2]|
                 |defined_input.zones[2].id|
                 |defined_input.services[2].zone_id|
                 (= |input.zones[2].id| |input.services[2].zone_id|)
                 (and |defined_input.zones[2].dmz|
                      (= |input.zones[2].dmz| true))
                 |defined_input.services[2]|
                 |defined_input.services[2]|))
      (a!63 (and true
                 (and true |defined_input.services[1]|)
                 |defined_input.zones[0]|
                 |defined_input.zones[0].id|
                 |defined_input.services[1].zone_id|
                 (= |input.zones[0].id| |input.services[1].zone_id|)
                 (and |defined_input.zones[0].dmz|
                      (= |input.zones[0].dmz| true))
                 |defined_input.services[1]|
                 |defined_input.services[1]|))
      (a!73 (and true
                 (and true |defined_input.services[1]|)
                 |defined_input.zones[1]|
                 |defined_input.zones[1].id|
                 |defined_input.services[1].zone_id|
                 (= |input.zones[1].id| |input.services[1].zone_id|)
                 (and |defined_input.zones[1].dmz|
                      (= |input.zones[1].dmz| true))
                 |defined_input.services[1]|
                 |defined_input.services[1]|))
      (a!83 (and true
                 (and true |defined_input.services[1]|)
                 |defined_input.zones[2]|
                 |defined_input.zones[2].id|
                 |defined_input.services[1].zone_id|
                 (= |input.zones[2].id| |input.services[1].zone_id|)
                 (and |defined_input.zones[2].dmz|
                      (= |input.zones[2].dmz| true))
                 |defined_input.services[1]|
                 |defined_input.services[1]|)))
(let ((a!2 (and (and a!1
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[0].name|
                          (= |input.connections[0].source|
                             |input.services[0].name|)))
                |defined_input.databases[0]|
                (and |defined_input.databases[0].name|
                     |defined_input.connections[0].target|
                     (= |input.databases[0].name| |input.connections[0].target|))
                (and |defined_input.databases[0].internal|
                     (= |input.databases[0].internal| true))
                |defined_input.services[0].name|))
      (a!3 (and (and a!1
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[0].name|
                          (= |input.connections[0].source|
                             |input.services[0].name|)))
                |defined_input.databases[1]|
                (and |defined_input.databases[1].name|
                     |defined_input.connections[0].target|
                     (= |input.databases[1].name| |input.connections[0].target|))
                (and |defined_input.databases[1].internal|
                     (= |input.databases[1].internal| true))
                |defined_input.services[0].name|))
      (a!4 (and (and a!1
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[0].name|
                          (= |input.connections[0].source|
                             |input.services[0].name|)))
                |defined_input.databases[2]|
                (and |defined_input.databases[2].name|
                     |defined_input.connections[0].target|
                     (= |input.databases[2].name| |input.connections[0].target|))
                (and |defined_input.databases[2].internal|
                     (= |input.databases[2].internal| true))
                |defined_input.services[0].name|))
      (a!5 (and (and a!1
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[0].name|
                          (= |input.connections[1].source|
                             |input.services[0].name|)))
                |defined_input.databases[0]|
                (and |defined_input.databases[0].name|
                     |defined_input.connections[1].target|
                     (= |input.databases[0].name| |input.connections[1].target|))
                (and |defined_input.databases[0].internal|
                     (= |input.databases[0].internal| true))
                |defined_input.services[0].name|))
      (a!6 (and (and a!1
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[0].name|
                          (= |input.connections[1].source|
                             |input.services[0].name|)))
                |defined_input.databases[1]|
                (and |defined_input.databases[1].name|
                     |defined_input.connections[1].target|
                     (= |input.databases[1].name| |input.connections[1].target|))
                (and |defined_input.databases[1].internal|
                     (= |input.databases[1].internal| true))
                |defined_input.services[0].name|))
      (a!7 (and (and a!1
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[0].name|
                          (= |input.connections[1].source|
                             |input.services[0].name|)))
                |defined_input.databases[2]|
                (and |defined_input.databases[2].name|
                     |defined_input.connections[1].target|
                     (= |input.databases[2].name| |input.connections[1].target|))
                (and |defined_input.databases[2].internal|
                     (= |input.databases[2].internal| true))
                |defined_input.services[0].name|))
      (a!8 (and (and a!1
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[0].name|
                          (= |input.connections[2].source|
                             |input.services[0].name|)))
                |defined_input.databases[0]|
                (and |defined_input.databases[0].name|
                     |defined_input.connections[2].target|
                     (= |input.databases[0].name| |input.connections[2].target|))
                (and |defined_input.databases[0].internal|
                     (= |input.databases[0].internal| true))
                |defined_input.services[0].name|))
      (a!9 (and (and a!1
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[0].name|
                          (= |input.connections[2].source|
                             |input.services[0].name|)))
                |defined_input.databases[1]|
                (and |defined_input.databases[1].name|
                     |defined_input.connections[2].target|
                     (= |input.databases[1].name| |input.connections[2].target|))
                (and |defined_input.databases[1].internal|
                     (= |input.databases[1].internal| true))
                |defined_input.services[0].name|))
      (a!10 (and (and a!1
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!12 (and (and a!11
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!13 (and (and a!11
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!14 (and (and a!11
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!15 (and (and a!11
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!16 (and (and a!11
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!17 (and (and a!11
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!18 (and (and a!11
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!19 (and (and a!11
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!20 (and (and a!11
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!22 (and (and a!21
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!23 (and (and a!21
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!24 (and (and a!21
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[0].name|
                           (= |input.connections[0].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!25 (and (and a!21
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!26 (and (and a!21
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!27 (and (and a!21
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[0].name|
                           (= |input.connections[1].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!28 (and (and a!21
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[0].name|))
      (a!29 (and (and a!21
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[0].name|))
      (a!30 (and (and a!21
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[0].name|
                           (= |input.connections[2].source|
                              |input.services[0].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[0].name|))
      (a!33 (and (and a!32
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!34 (and (and a!32
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!35 (and (and a!32
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!36 (and (and a!32
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!37 (and (and a!32
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!38 (and (and a!32
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!39 (and (and a!32
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!40 (and (and a!32
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!41 (and (and a!32
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!43 (and (and a!42
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!44 (and (and a!42
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!45 (and (and a!42
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!46 (and (and a!42
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!47 (and (and a!42
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!48 (and (and a!42
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!49 (and (and a!42
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!50 (and (and a!42
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!51 (and (and a!42
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!53 (and (and a!52
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!54 (and (and a!52
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!55 (and (and a!52
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[2].name|
                           (= |input.connections[0].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!56 (and (and a!52
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!57 (and (and a!52
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!58 (and (and a!52
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[2].name|
                           (= |input.connections[1].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!59 (and (and a!52
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[2].name|))
      (a!60 (and (and a!52
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[2].name|))
      (a!61 (and (and a!52
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[2].name|
                           (= |input.connections[2].source|
                              |input.services[2].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[2].name|))
      (a!64 (and (and a!63
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!65 (and (and a!63
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!66 (and (and a!63
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!67 (and (and a!63
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!68 (and (and a!63
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!69 (and (and a!63
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!70 (and (and a!63
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!71 (and (and a!63
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!72 (and (and a!63
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!74 (and (and a!73
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!75 (and (and a!73
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!76 (and (and a!73
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!77 (and (and a!73
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!78 (and (and a!73
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!79 (and (and a!73
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!80 (and (and a!73
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!81 (and (and a!73
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!82 (and (and a!73
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!84 (and (and a!83
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[0].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!85 (and (and a!83
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[1].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!86 (and (and a!83
                      |defined_input.connections[0]|
                      (and |defined_input.connections[0].source|
                           |defined_input.services[1].name|
                           (= |input.connections[0].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[0].target|
                      (= |input.databases[2].name|
                         |input.connections[0].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!87 (and (and a!83
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[0].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!88 (and (and a!83
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[1].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!89 (and (and a!83
                      |defined_input.connections[1]|
                      (and |defined_input.connections[1].source|
                           |defined_input.services[1].name|
                           (= |input.connections[1].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[1].target|
                      (= |input.databases[2].name|
                         |input.connections[1].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|))
      (a!90 (and (and a!83
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[0]|
                 (and |defined_input.databases[0].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[0].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[0].internal|
                      (= |input.databases[0].internal| true))
                 |defined_input.services[1].name|))
      (a!91 (and (and a!83
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[1]|
                 (and |defined_input.databases[1].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[1].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[1].internal|
                      (= |input.databases[1].internal| true))
                 |defined_input.services[1].name|))
      (a!92 (and (and a!83
                      |defined_input.connections[2]|
                      (and |defined_input.connections[2].source|
                           |defined_input.services[1].name|
                           (= |input.connections[2].source|
                              |input.services[1].name|)))
                 |defined_input.databases[2]|
                 (and |defined_input.databases[2].name|
                      |defined_input.connections[2].target|
                      (= |input.databases[2].name|
                         |input.connections[2].target|))
                 (and |defined_input.databases[2].internal|
                      (= |input.databases[2].internal| true))
                 |defined_input.services[1].name|)))
(let ((a!31 (or a!2
                a!3
                a!4
                a!5
                a!6
                a!7
                a!8
                a!9
                a!10
                a!12
                a!13
                a!14
                a!15
                a!16
                a!17
                a!18
                a!19
                a!20
                a!22
                a!23
                a!24
                a!25
                a!26
                a!27
                a!28
                a!29
                a!30
                (and (and (and true |defined_input.services[0]|)
                          |defined_input.services[0].handles_pii|
                          (= |input.services[0].handles_pii| true))
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[0].name|
                          (= |input.connections[0].source|
                             |input.services[0].name|))
                     (and |defined_input.connections[0].encrypted|
                          (= |input.connections[0].encrypted| false))
                     |defined_input.services[0].name|)
                (and (and (and true |defined_input.services[0]|)
                          |defined_input.services[0].handles_pii|
                          (= |input.services[0].handles_pii| true))
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[0].name|
                          (= |input.connections[1].source|
                             |input.services[0].name|))
                     (and |defined_input.connections[1].encrypted|
                          (= |input.connections[1].encrypted| false))
                     |defined_input.services[0].name|)
                (and (and (and true |defined_input.services[0]|)
                          |defined_input.services[0].handles_pii|
                          (= |input.services[0].handles_pii| true))
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[0].name|
                          (= |input.connections[2].source|
                             |input.services[0].name|))
                     (and |defined_input.connections[2].encrypted|
                          (= |input.connections[2].encrypted| false))
                     |defined_input.services[0].name|)))
      (a!62 (or a!33
                a!34
                a!35
                a!36
                a!37
                a!38
                a!39
                a!40
                a!41
                a!43
                a!44
                a!45
                a!46
                a!47
                a!48
                a!49
                a!50
                a!51
                a!53
                a!54
                a!55
                a!56
                a!57
                a!58
                a!59
                a!60
                a!61
                (and (and (and true |defined_input.services[2]|)
                          |defined_input.services[2].handles_pii|
                          (= |input.services[2].handles_pii| true))
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[2].name|
                          (= |input.connections[0].source|
                             |input.services[2].name|))
                     (and |defined_input.connections[0].encrypted|
                          (= |input.connections[0].encrypted| false))
                     |defined_input.services[2].name|)
                (and (and (and true |defined_input.services[2]|)
                          |defined_input.services[2].handles_pii|
                          (= |input.services[2].handles_pii| true))
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[2].name|
                          (= |input.connections[1].source|
                             |input.services[2].name|))
                     (and |defined_input.connections[1].encrypted|
                          (= |input.connections[1].encrypted| false))
                     |defined_input.services[2].name|)
                (and (and (and true |defined_input.services[2]|)
                          |defined_input.services[2].handles_pii|
                          (= |input.services[2].handles_pii| true))
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[2].name|
                          (= |input.connections[2].source|
                             |input.services[2].name|))
                     (and |defined_input.connections[2].encrypted|
                          (= |input.connections[2].encrypted| false))
                     |defined_input.services[2].name|)))
      (a!93 (or a!64
                a!65
                a!66
                a!67
                a!68
                a!69
                a!70
                a!71
                a!72
                a!74
                a!75
                a!76
                a!77
                a!78
                a!79
                a!80
                a!81
                a!82
                a!84
                a!85
                a!86
                a!87
                a!88
                a!89
                a!90
                a!91
                a!92
                (and (and (and true |defined_input.services[1]|)
                          |defined_input.services[1].handles_pii|
                          (= |input.services[1].handles_pii| true))
                     |defined_input.connections[0]|
                     (and |defined_input.connections[0].source|
                          |defined_input.services[1].name|
                          (= |input.connections[0].source|
                             |input.services[1].name|))
                     (and |defined_input.connections[0].encrypted|
                          (= |input.connections[0].encrypted| false))
                     |defined_input.services[1].name|)
                (and (and (and true |defined_input.services[1]|)
                          |defined_input.services[1].handles_pii|
                          (= |input.services[1].handles_pii| true))
                     |defined_input.connections[1]|
                     (and |defined_input.connections[1].source|
                          |defined_input.services[1].name|
                          (= |input.connections[1].source|
                             |input.services[1].name|))
                     (and |defined_input.connections[1].encrypted|
                          (= |input.connections[1].encrypted| false))
                     |defined_input.services[1].name|)
                (and (and (and true |defined_input.services[1]|)
                          |defined_input.services[1].handles_pii|
                          (= |input.services[1].handles_pii| true))
                     |defined_input.connections[2]|
                     (and |defined_input.connections[2].source|
                          |defined_input.services[1].name|
                          (= |input.connections[2].source|
                             |input.services[1].name|))
                     (and |defined_input.connections[2].encrypted|
                          (= |input.connections[2].encrypted| false))
                     |defined_input.services[1].name|))))
(let ((a!94 (and true
                 (= (+ 0 (ite a!31 1 0) (ite a!62 1 0) (ite a!93 1 0)) 0)
                 true)))
  (= (ite a!94 true false) false))))))
